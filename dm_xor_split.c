/*
 * dm_xor_split.c — Device-mapper target that XOR-splits data across N disks.
 *
 * DESIGN GOALS (this version):
 *   1. Correctness above all — no performance tricks.
 *   2. Zero reliance on bio iterator state after the initial walk.
 *      All segment info is saved into plain arrays at map() entry.
 *      Encode, decode, and cleanup use simple for-loops over those arrays.
 *   3. Minimal code surface — easy to audit.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/workqueue.h>

#include "xor_core.h"

#define DM_MSG_PREFIX      "dm_xor_split"
#define MAX_SPLIT_DEVICES  8

/*
 * Maximum bio size we accept (in 512-byte sectors).
 * 128 sectors = 64 KB.  ti->max_io_len is set to this so DM will split
 * any larger bio before it reaches map().
 *
 * Worst-case segments per bio:  64 KB / PAGE_SIZE + 1 (misaligned) = 17
 * on a 4 KB-page system.  We use 32 for headroom.
 */
#define XOR_MAX_IO_SECTORS 128
#define XOR_MAX_SEGS       32

/*
 * Bioset pool size.  Must be >= MAX_SPLIT_DEVICES so a single map() call
 * can allocate all clone bios from the emergency pool without deadlocking
 * (the clones aren't submitted until ALL are allocated).
 */
#define XOR_BIO_POOL_SIZE  (MAX_SPLIT_DEVICES * 4)

static struct workqueue_struct *xor_decode_wq;

static bool verbose;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Log every map() call to dmesg");

/* ------------------------------------------------------------------ */
/* Per-DM-table context                                                */
/* ------------------------------------------------------------------ */

struct xor_split_ctx {
    int            dev_count;
    struct dm_dev *devs[MAX_SPLIT_DEVICES];
    struct bio_set bio_set;
};

/* ------------------------------------------------------------------ */
/* Per-IO tracker                                                      */
/*                                                                     */
/* All segment/page info is captured once at map() and stored in plain  */
/* arrays.  Encode, decode, and cleanup iterate these arrays with       */
/* simple for-loops — no bio iterators are touched after map().         */
/* ------------------------------------------------------------------ */

struct saved_seg {
    struct page  *page;      /* original bio's page for this segment */
    unsigned int  offset;    /* offset within that page              */
    unsigned int  len;       /* bytes in this segment                */
};

struct xor_io_tracker {
    struct xor_split_ctx *ctx;
    struct bio           *orig_bio;
    atomic_t              pending;
    blk_status_t          status;
    int                   dev_count;
    int                   n_segs;          /* 0 for thin-clone ops */
    struct work_struct    decode_work;

    struct saved_seg  segs[XOR_MAX_SEGS];

    /* bounce[device][segment] — pages we own, freed with __free_page */
    struct page      *bounce[MAX_SPLIT_DEVICES][XOR_MAX_SEGS];

    struct bio       *clones[MAX_SPLIT_DEVICES];
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void kernel_random_wrapper(void *buf, size_t nbytes)
{
    get_random_bytes(buf, (int)nbytes);
}

static void free_bounce_pages(struct xor_io_tracker *t)
{
    int d, s;
    for (d = 0; d < t->dev_count; d++)
        for (s = 0; s < t->n_segs; s++)
            if (t->bounce[d][s]) {
                __free_page(t->bounce[d][s]);
                t->bounce[d][s] = NULL;
            }
}

static void free_clones(struct xor_io_tracker *t)
{
    int d;
    for (d = 0; d < t->dev_count; d++)
        if (t->clones[d]) {
            bio_put(t->clones[d]);
            t->clones[d] = NULL;
        }
}

static void complete_orig(struct xor_io_tracker *t)
{
    t->orig_bio->bi_status = t->status;
    bio_endio(t->orig_bio);
    kfree(t);
}

/* ------------------------------------------------------------------ */
/* Decode worker — runs in process context (workqueue)                 */
/* ------------------------------------------------------------------ */

static void xor_decode_worker(struct work_struct *work)
{
    struct xor_io_tracker *t =
        container_of(work, struct xor_io_tracker, decode_work);
    int s, d;

    for (s = 0; s < t->n_segs; s++) {
        uint8_t *src_bufs[MAX_SPLIT_DEVICES];
        void    *dst;

        dst = kmap_local_page(t->segs[s].page) + t->segs[s].offset;
        for (d = 0; d < t->dev_count; d++)
            src_bufs[d] = kmap_local_page(t->bounce[d][s]);

        xor_split_decode(src_bufs, dst, t->dev_count, t->segs[s].len);

        /* kunmap_local must be called in reverse (LIFO) order */
        for (d = t->dev_count - 1; d >= 0; d--)
            kunmap_local(src_bufs[d]);
        kunmap_local(dst);
    }

    free_bounce_pages(t);
    free_clones(t);
    complete_orig(t);
}

/* ------------------------------------------------------------------ */
/* End-IO callback (may run in interrupt / softirq context)            */
/* ------------------------------------------------------------------ */

static void xor_end_io(struct bio *clone)
{
    struct xor_io_tracker *t = clone->bi_private;

    /* Propagate error.  blk_status_t is a single byte — stores are
     * naturally atomic on every architecture Linux supports.  We only
     * need *some* error to survive, not a specific one. */
    if (clone->bi_status != BLK_STS_OK)
        t->status = clone->bi_status;

    if (!atomic_dec_and_test(&t->pending))
        return;   /* other clones still in flight */

    /* All clones completed */
    if (bio_data_dir(t->orig_bio) == READ &&
        t->status == BLK_STS_OK &&
        t->n_segs > 0) {
        /* XOR decode needs kmap_local_page → must run in process context */
        INIT_WORK(&t->decode_work, xor_decode_worker);
        queue_work(xor_decode_wq, &t->decode_work);
        return;
    }

    /* WRITE / FLUSH / DISCARD / WRITE_ZEROES / error */
    free_bounce_pages(t);
    free_clones(t);
    complete_orig(t);
}

/* ------------------------------------------------------------------ */
/* Map                                                                 */
/* ------------------------------------------------------------------ */

static int xor_split_map(struct dm_target *ti, struct bio *bio)
{
    struct xor_split_ctx  *ctx = ti->private;
    struct xor_io_tracker *t;
    enum req_op op = bio_op(bio);
    bool needs_bounce;
    int d, s;

    /* ---- Classify ------------------------------------------------- */
    if (bio->bi_opf & REQ_PREFLUSH) {
        if (!bio_sectors(bio)) {
            needs_bounce = false;           /* pure flush */
        } else {
            bio->bi_opf &= ~REQ_PREFLUSH;  /* flush+data: handle data part */
            needs_bounce = true;
        }
    } else {
        needs_bounce = (op == REQ_OP_READ || op == REQ_OP_WRITE);
    }

    /* ---- Allocate tracker ----------------------------------------- */
    t = kzalloc(sizeof(*t), GFP_NOIO);
    if (!t)
        return DM_MAPIO_REQUEUE;

    t->ctx       = ctx;
    t->orig_bio  = bio;
    t->status    = BLK_STS_OK;
    t->dev_count = ctx->dev_count;
    t->n_segs    = 0;
    atomic_set(&t->pending, ctx->dev_count);

    if (verbose)
        pr_info("[%s] map: op=%u sector=%llu size=%u bounce=%d\n",
                DM_MSG_PREFIX, (__force unsigned)op,
                (unsigned long long)bio->bi_iter.bi_sector,
                bio->bi_iter.bi_size, (int)needs_bounce);

    /* ---- Step 1: Snapshot segment table from original bio ---------- */
    /*                                                                  */
    /* This is the ONE AND ONLY place we use bio_for_each_segment.      */
    /* After this loop, bio->bi_iter is unchanged (the macro only       */
    /* modifies its local iterator variable).  All subsequent code uses */
    /* t->segs[] and t->bounce[][] via plain for-loops.                 */

    if (needs_bounce) {
        struct bio_vec  bv;
        struct bvec_iter iter;

        bio_for_each_segment(bv, bio, iter) {
            if (t->n_segs >= XOR_MAX_SEGS) {
                pr_err("[%s] bio too many segments (%d >= %d)\n",
                       DM_MSG_PREFIX, t->n_segs, XOR_MAX_SEGS);
                kfree(t);
                return DM_MAPIO_REQUEUE;
            }
            t->segs[t->n_segs].page   = bv.bv_page;
            t->segs[t->n_segs].offset = bv.bv_offset;
            t->segs[t->n_segs].len    = bv.bv_len;
            t->n_segs++;
        }
    }

    /* ---- Step 2: Allocate bounce pages ----------------------------- */
    if (needs_bounce) {
        for (d = 0; d < ctx->dev_count; d++) {
            for (s = 0; s < t->n_segs; s++) {
                t->bounce[d][s] = alloc_page(GFP_NOIO);
                if (!t->bounce[d][s])
                    goto fail;
            }
        }
    }

    /* ---- Step 3: XOR-encode for writes ----------------------------- */
    if (needs_bounce && bio_data_dir(bio) == WRITE) {
        for (s = 0; s < t->n_segs; s++) {
            uint8_t *dst_bufs[MAX_SPLIT_DEVICES];
            void    *src;

            src = kmap_local_page(t->segs[s].page) + t->segs[s].offset;
            for (d = 0; d < ctx->dev_count; d++)
                dst_bufs[d] = kmap_local_page(t->bounce[d][s]);

            xor_split_encode(src, dst_bufs, ctx->dev_count,
                             t->segs[s].len, kernel_random_wrapper);

            for (d = ctx->dev_count - 1; d >= 0; d--)
                kunmap_local(dst_bufs[d]);
            kunmap_local(src);
        }
    }

    /* ---- Step 4: Build clone bios --------------------------------- */
    for (d = 0; d < ctx->dev_count; d++) {
        struct bio *clone;
        int nr_vecs = needs_bounce ? t->n_segs : 0;

        clone = bio_alloc_bioset(ctx->devs[d]->bdev, nr_vecs,
                                 bio->bi_opf, GFP_NOIO, &ctx->bio_set);
        if (!clone)
            goto fail;

        t->clones[d]      = clone;
        clone->bi_private  = t;
        clone->bi_end_io   = xor_end_io;
        clone->bi_iter.bi_sector = bio->bi_iter.bi_sector;

        if (needs_bounce) {
            for (s = 0; s < t->n_segs; s++) {
                if (bio_add_page(clone, t->bounce[d][s],
                                 t->segs[s].len, 0) < t->segs[s].len) {
                    pr_err("[%s] bio_add_page failed\n", DM_MSG_PREFIX);
                    goto fail;
                }
            }
        } else {
            /* Thin clone for FLUSH/DISCARD/WRITE_ZEROES */
            clone->bi_iter.bi_size = bio->bi_iter.bi_size;
        }
    }

    /* ---- Step 5: Submit ------------------------------------------- */
    for (d = 0; d < ctx->dev_count; d++)
        submit_bio(t->clones[d]);

    return DM_MAPIO_SUBMITTED;

fail:
    free_clones(t);
    free_bounce_pages(t);
    kfree(t);
    return DM_MAPIO_REQUEUE;
}

/* ------------------------------------------------------------------ */
/* Constructor                                                         */
/* ------------------------------------------------------------------ */

static int xor_split_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct xor_split_ctx *ctx;
    int i, r;

    if (argc < 2 || argc > MAX_SPLIT_DEVICES) {
        ti->error = "Require between 2 and 8 device paths";
        return -EINVAL;
    }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->dev_count = argc;

    r = bioset_init(&ctx->bio_set, XOR_BIO_POOL_SIZE, 0,
                    BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r) {
        ti->error = "Cannot init bioset";
        goto bad_ctx;
    }

    for (i = 0; i < argc; i++) {
        r = dm_get_device(ti, argv[i], dm_table_get_mode(ti->table),
                          &ctx->devs[i]);
        if (r) {
            ti->error = "Cannot open backing device";
            pr_err("[%s] ctr: dm_get_device(%s) failed: %d\n",
                   DM_MSG_PREFIX, argv[i], r);
            goto bad_devs;
        }
    }

    /*
     * Route special bio types through map() so DM never falls back to
     * its own (very slow) sector-by-sector emulation.
     *
     * max_io_len caps bio size so we never exceed XOR_MAX_SEGS bounce
     * pages per device.
     */
    ti->num_flush_bios        = 1;
    ti->num_discard_bios      = 1;
    ti->num_write_zeroes_bios = 1;
    ti->max_io_len            = XOR_MAX_IO_SECTORS;

    ti->private = ctx;
    pr_info("[%s] ctr: %d devices, max_io_len=%u, ready\n",
            DM_MSG_PREFIX, argc, XOR_MAX_IO_SECTORS);
    return 0;

bad_devs:
    while (--i >= 0)
        dm_put_device(ti, ctx->devs[i]);
    bioset_exit(&ctx->bio_set);
bad_ctx:
    kfree(ctx);
    return r;
}

/* ------------------------------------------------------------------ */
/* Destructor                                                          */
/* ------------------------------------------------------------------ */

static void xor_split_dtr(struct dm_target *ti)
{
    struct xor_split_ctx *ctx = ti->private;
    int i;

    drain_workqueue(xor_decode_wq);

    for (i = 0; i < ctx->dev_count; i++)
        dm_put_device(ti, ctx->devs[i]);

    bioset_exit(&ctx->bio_set);
    kfree(ctx);
    pr_info("[%s] dtr: done\n", DM_MSG_PREFIX);
}

/* ------------------------------------------------------------------ */
/* Module plumbing                                                     */
/* ------------------------------------------------------------------ */

static struct target_type xor_split_target = {
    .name    = "xor_split",
    .version = {1, 0, 0},
    .module  = THIS_MODULE,
    .ctr     = xor_split_ctr,
    .dtr     = xor_split_dtr,
    .map     = xor_split_map,
};

static int __init dm_xor_split_init(void)
{
    int r;

    xor_decode_wq = alloc_workqueue("dm_xor_decode",
                                    WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!xor_decode_wq)
        return -ENOMEM;

    r = dm_register_target(&xor_split_target);
    if (r < 0) {
        destroy_workqueue(xor_decode_wq);
        return r;
    }

    pr_info("[%s] loaded\n", DM_MSG_PREFIX);
    return 0;
}

static void __exit dm_xor_split_exit(void)
{
    dm_unregister_target(&xor_split_target);
    destroy_workqueue(xor_decode_wq);
    pr_info("[%s] unloaded\n", DM_MSG_PREFIX);
}

module_init(dm_xor_split_init);
module_exit(dm_xor_split_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR split device mapper");
