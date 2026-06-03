#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/atomic.h>

#include "xor_core.h"

#define DM_MSG_PREFIX     "dm_xor_split"
#define MAX_SPLIT_DEVICES 8

/*
 * Pool size and per-bio I/O limit.
 * MAX bounce pages per I/O = XOR_MAX_IO_SECTORS * SECTOR_SIZE / PAGE_SIZE
 *                           * MAX_SPLIT_DEVICES
 * = 128 * 512 / 4096 * 8 = 128 pages.
 * Pool of 512 pages → 4 fully-concurrent large I/Os without slab pressure.
 */
#define MIN_POOL_PAGES    512
#define XOR_MAX_IO_SECTORS 128   /* 64 KB per bio split */

/* -------------------------------------------------------------------------
 * Module parameters
 * ------------------------------------------------------------------------- */
static bool verbose = false;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Log every bio lifecycle (map+end_io+decode). "
                           "Each bio gets a unique ID so hung bios are visible.");

static struct workqueue_struct *xor_decode_wq;

/*
 * Global bio counter — gives each tracker a unique ID so we can match
 * "bio#N submitted" against "bio#N decoded" in dmesg.
 * If a bio#N is submitted but never decoded, the missing disk completion
 * log ("bio#N disk X done") tells us exactly which clone hung.
 */
static atomic_t g_bio_id = ATOMIC_INIT(0);

static const char *xor_op_name(unsigned int op)
{
    switch (op) {
    case REQ_OP_READ:         return "READ";
    case REQ_OP_WRITE:        return "WRITE";
    case REQ_OP_DISCARD:      return "DISCARD";
    case REQ_OP_SECURE_ERASE: return "SECURE_ERASE";
    case REQ_OP_WRITE_ZEROES: return "WRITE_ZEROES";
    case REQ_OP_FLUSH:        return "FLUSH";
    default:                  return "UNKNOWN";
    }
}

struct xor_split_ctx {
    int dev_count;
    struct dm_dev *devs[MAX_SPLIT_DEVICES];
    struct bio_set bio_set;
    mempool_t bounce_pool;
};

struct xor_io_tracker {
    struct xor_split_ctx *ctx;
    struct bio           *orig_bio;
    atomic_t              pending_bios;
    blk_status_t          bi_status;   /* Fix #1: only via cmpxchg */
    int                   dev_count;
    struct bio           *cloned_bios[MAX_SPLIT_DEVICES];
    struct work_struct    decode_work;
    bool                  has_bounce_pages;
    u32                   bio_id;       /* unique ID for log correlation */
};

static void kernel_random_wrapper(void *buf, size_t nbytes) {
    get_random_bytes(buf, (int)nbytes);
}

/* Shared cleanup: free bounce pages (if any) then release the clone bio */
static void xor_free_clone(struct xor_io_tracker *tracker, int idx)
{
    struct bio *clone = tracker->cloned_bios[idx];
    if (!clone)
        return;
    if (tracker->has_bounce_pages) {
        int v;
        /* Fix #3: walk bi_io_vec directly — bi_size == 0 after completion */
        for (v = 0; v < clone->bi_vcnt; v++) {
            struct bio_vec *bv = &clone->bi_io_vec[v];
            if (bv->bv_page)
                mempool_free(bv->bv_page, &tracker->ctx->bounce_pool);
        }
    }
    bio_put(clone);
}

/* Fix #4/#5: XOR decode in process context on WQ_MEM_RECLAIM workqueue */
static void xor_decode_worker(struct work_struct *work)
{
    struct xor_io_tracker *tracker =
        container_of(work, struct xor_io_tracker, decode_work);
    struct bio *orig = tracker->orig_bio;
    int i;

    if (verbose)
        pr_info("[%s] bio#%u DECODE start  sector=%llu\n",
                DM_MSG_PREFIX, tracker->bio_id,
                (unsigned long long)orig->bi_iter.bi_sector);

    {
        struct bio_vec bv_dst;
        struct bvec_iter iter_dst;
        int seg_idx = 0;

        bio_for_each_segment(bv_dst, orig, iter_dst) {
            uint8_t *mapped_srcs[MAX_SPLIT_DEVICES];
            void *dst_page_addr =
                kmap_local_page(bv_dst.bv_page) + bv_dst.bv_offset;
            int disk_idx;

            for (disk_idx = 0; disk_idx < tracker->dev_count; disk_idx++) {
                struct bio *clone_bio = tracker->cloned_bios[disk_idx];
                struct bio_vec *bv_src = &clone_bio->bi_io_vec[seg_idx];
                mapped_srcs[disk_idx] = kmap_local_page(bv_src->bv_page);
            }

            xor_split_decode(mapped_srcs, dst_page_addr,
                             tracker->dev_count, bv_dst.bv_len);

            for (disk_idx = tracker->dev_count - 1; disk_idx >= 0; disk_idx--)
                kunmap_local(mapped_srcs[disk_idx]);
            kunmap_local(dst_page_addr);
            seg_idx++;
        }
    }

    for (i = 0; i < tracker->dev_count; i++)
        xor_free_clone(tracker, i);

    if (verbose)
        pr_info("[%s] bio#%u DECODE done   sector=%llu status=%u → bio_endio\n",
                DM_MSG_PREFIX, tracker->bio_id,
                (unsigned long long)orig->bi_iter.bi_sector,
                (unsigned)tracker->bi_status);

    orig->bi_status = tracker->bi_status;
    bio_endio(orig);
    kfree(tracker);
}

static void xor_split_end_io(struct bio *clone) {
    struct xor_io_tracker *tracker = clone->bi_private;
    struct bio *orig = tracker->orig_bio;
    int remaining;
    int i;

    /* Fix #1: atomic compare-and-exchange for concurrent error propagation */
    if (clone->bi_status != BLK_STS_OK)
        cmpxchg(&tracker->bi_status, BLK_STS_OK, clone->bi_status);

    remaining = atomic_dec_return(&tracker->pending_bios);

    if (verbose)
        pr_info("[%s] bio#%u clone done   sector=%llu status=%u pending=%d\n",
                DM_MSG_PREFIX, tracker->bio_id,
                (unsigned long long)orig->bi_iter.bi_sector,
                (unsigned)clone->bi_status, remaining);

    if (remaining > 0)
        return;

    /* All clones done */
    if (bio_data_dir(orig) == READ &&
        tracker->bi_status == BLK_STS_OK &&
        tracker->has_bounce_pages) {
        /* Fix #4/#5: defer XOR decode to private WQ_MEM_RECLAIM workqueue */
        INIT_WORK(&tracker->decode_work, xor_decode_worker);
        queue_work(xor_decode_wq, &tracker->decode_work);
        return;
    }

    /* Write / DISCARD / WRITE_ZEROES / FLUSH / error: complete synchronously */
    for (i = 0; i < tracker->dev_count; i++)
        xor_free_clone(tracker, i);

    if (verbose)
        pr_info("[%s] bio#%u WRITE/MISC done sector=%llu status=%u → bio_endio\n",
                DM_MSG_PREFIX, tracker->bio_id,
                (unsigned long long)orig->bi_iter.bi_sector,
                (unsigned)tracker->bi_status);

    orig->bi_status = tracker->bi_status;
    bio_endio(orig);
    kfree(tracker);
}

/* -------------------------------------------------------------------------
 * Main map function
 * ------------------------------------------------------------------------- */
static int xor_split_map(struct dm_target *ti, struct bio *bio) {
    struct xor_split_ctx *ctx = ti->private;
    struct xor_io_tracker *tracker;
    unsigned int op = bio_op(bio);
    bool needs_bounce;
    int i, j;

    /* ------------------------------------------------------------------
     * Bio classification
     *
     * needs_bounce = true:  READ / WRITE — allocate per-disk bounce pages,
     *                       XOR-encode writes, decode reads in the worker.
     *
     * needs_bounce = false: Operations carrying no page data:
     *   • Pure flush (REQ_PREFLUSH, no sectors): forward to all disks so
     *     their write caches are actually committed.
     *   • DISCARD / WRITE_ZEROES / SECURE_ERASE: thin 0-bvec clones.
     *
     * Fix #7  — strip PREFLUSH from flush+data bios and handle data.
     * Fix #8  — for data bios copy only bi_sector (not bi_iter) so
     *            bio_add_page accumulates bi_size from zero; previously
     *            bi_size ended up doubled.
     * Fix #9  — ti->num_discard_bios / num_write_zeroes_bios / num_flush_bios
     *            set in ctr so DM routes these through map() instead of
     *            falling back to sector-by-sector emulation (=several min).
     * ------------------------------------------------------------------ */
    if (bio->bi_opf & REQ_PREFLUSH) {
        if (!bio_sectors(bio)) {
            needs_bounce = false;   /* pure flush: forward as thin clone */
        } else {
            bio->bi_opf &= ~REQ_PREFLUSH;  /* flush+data: strip, handle data */
            needs_bounce = true;
        }
    } else {
        needs_bounce = (op == REQ_OP_READ || op == REQ_OP_WRITE);
    }

    /* Allocate tracker -------------------------------------------------- */
    tracker = kzalloc(sizeof(struct xor_io_tracker), GFP_NOIO);
    if (!tracker) return DM_MAPIO_REQUEUE;

    tracker->ctx              = ctx;
    tracker->orig_bio         = bio;
    tracker->bi_status        = BLK_STS_OK;
    tracker->dev_count        = ctx->dev_count;
    tracker->has_bounce_pages = needs_bounce;
    tracker->bio_id           = (u32)atomic_inc_return(&g_bio_id);
    atomic_set(&tracker->pending_bios, ctx->dev_count);

    /* Diagnostic logging ------------------------------------------------ */
    if (verbose) {
        pr_info("[%s] bio#%u MAP  op=%-12s sector=%-10llu size_kb=%-6u segs=%u opf=0x%x bounce=%d\n",
                DM_MSG_PREFIX, tracker->bio_id, xor_op_name(op),
                (unsigned long long)bio->bi_iter.bi_sector,
                bio->bi_iter.bi_size >> 10,
                bio_segments(bio),
                bio->bi_opf,
                (int)needs_bounce);
    } else if (!needs_bounce) {
        /* Always log unusual ops without rate-limiting */
        pr_info("[%s] MAP op=%-12s sector=%-10llu size_kb=%u segs=%u\n",
                DM_MSG_PREFIX, xor_op_name(op),
                (unsigned long long)bio->bi_iter.bi_sector,
                bio->bi_iter.bi_size >> 10,
                bio_segments(bio));
    }

    /* PHASE 1: Allocate per-disk clone bios ----------------------------- */
    for (i = 0; i < ctx->dev_count; i++) {
        struct bio *clone;
        int nr_vecs = needs_bounce ? bio_segments(bio) : 0;

        clone = bio_alloc_bioset(ctx->devs[i]->bdev, nr_vecs,
                                 bio->bi_opf, GFP_NOIO, &ctx->bio_set);
        if (!clone) goto allocation_failed;

        tracker->cloned_bios[i] = clone;
        clone->bi_private = tracker;
        clone->bi_end_io  = xor_split_end_io;

        if (needs_bounce) {
            struct bio_vec bv;
            struct bvec_iter iter;

            /* Fix #8: only copy bi_sector for data bios */
            clone->bi_iter.bi_sector = bio->bi_iter.bi_sector;

            /* Fix #2: bounce pages from mempool, not raw alloc_page */
            bio_for_each_segment(bv, bio, iter) {
                struct page *bounce_page =
                    mempool_alloc(&ctx->bounce_pool, GFP_NOIO);
                if (!bounce_page) goto allocation_failed;

                if (bio_add_page(clone, bounce_page, bv.bv_len, 0) < bv.bv_len) {
                    pr_err("[%s] bio#%u bio_add_page failed (bv_len=%u)\n",
                           DM_MSG_PREFIX, tracker->bio_id, bv.bv_len);
                    mempool_free(bounce_page, &ctx->bounce_pool);
                    goto allocation_failed;
                }
            }
        } else {
            /* Thin clone: copy sector + size but no bvec pages */
            clone->bi_iter.bi_sector = bio->bi_iter.bi_sector;
            clone->bi_iter.bi_size   = bio->bi_iter.bi_size;
        }
    }

    /* PHASE 2: XOR-encode source data into bounce pages (writes only) --- */
    if (needs_bounce && bio_data_dir(bio) == WRITE) {
        int seg_idx = 0;
        struct bio_vec bv_src;
        struct bvec_iter iter_src;

        bio_for_each_segment(bv_src, bio, iter_src) {
            uint8_t *mapped_addrs[MAX_SPLIT_DEVICES];
            void *src_addr = kmap_local_page(bv_src.bv_page) + bv_src.bv_offset;
            int disk_idx;

            for (disk_idx = 0; disk_idx < ctx->dev_count; disk_idx++) {
                struct bio *clone = tracker->cloned_bios[disk_idx];
                struct bio_vec *bv_dst = &clone->bi_io_vec[seg_idx];
                mapped_addrs[disk_idx] = kmap_local_page(bv_dst->bv_page);
            }

            xor_split_encode(src_addr, mapped_addrs, ctx->dev_count,
                             bv_src.bv_len, kernel_random_wrapper);

            for (disk_idx = ctx->dev_count - 1; disk_idx >= 0; disk_idx--)
                kunmap_local(mapped_addrs[disk_idx]);
            kunmap_local(src_addr);
            seg_idx++;
        }
    }

    /* PHASE 3: Submit all clones asynchronously ------------------------- */
    for (i = 0; i < ctx->dev_count; i++)
        submit_bio(tracker->cloned_bios[i]);

    return DM_MAPIO_SUBMITTED;

allocation_failed:
    for (j = 0; j < ctx->dev_count; j++)
        xor_free_clone(tracker, j);
    kfree(tracker);
    return DM_MAPIO_REQUEUE;
}

/* -------------------------------------------------------------------------
 * Constructor
 * ------------------------------------------------------------------------- */
static int xor_split_ctr(struct dm_target *ti, unsigned int argc, char **argv) {
    struct xor_split_ctx *ctx;
    ktime_t t_start = ktime_get();
    int i, r;

    pr_info("[%s] ctr: %d device(s) requested\n", DM_MSG_PREFIX, argc);

    if (argc < 2 || argc > MAX_SPLIT_DEVICES) {
        ti->error = "Invalid argument count. Provide between 2 and 8 raw target disks.";
        return -EINVAL;
    }

    ctx = kzalloc(sizeof(struct xor_split_ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;

    ctx->dev_count = argc;

    pr_info("[%s] ctr: calling bioset_init...\n", DM_MSG_PREFIX);
    r = bioset_init(&ctx->bio_set, BIO_POOL_SIZE, 0,
                    BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r) { ti->error = "Bioset initialization failure"; goto bad_ctx; }
    pr_info("[%s] ctr: bioset_init OK\n", DM_MSG_PREFIX);

    pr_info("[%s] ctr: calling mempool_init_page_pool (min=%d pages = %lu KB)...\n",
            DM_MSG_PREFIX, MIN_POOL_PAGES,
            (unsigned long)(MIN_POOL_PAGES * PAGE_SIZE / 1024));
    r = mempool_init_page_pool(&ctx->bounce_pool, MIN_POOL_PAGES, 0);
    if (r) { ti->error = "Bounce pool init failure"; goto bad_bioset; }
    pr_info("[%s] ctr: mempool_init OK\n", DM_MSG_PREFIX);

    for (i = 0; i < argc; i++) {
        pr_info("[%s] ctr: dm_get_device[%d] = %s ...\n", DM_MSG_PREFIX, i, argv[i]);
        r = dm_get_device(ti, argv[i], dm_table_get_mode(ti->table), &ctx->devs[i]);
        if (r) {
            ti->error = "Target disk path acquisition failure";
            pr_err("[%s] ctr: dm_get_device[%d] FAILED for %s (err=%d)\n",
                   DM_MSG_PREFIX, i, argv[i], r);
            goto bad_devs;
        }
        /* No get_capacity() here: ABBA deadlock with DM table lock */
        pr_info("[%s] ctr: dm_get_device[%d] = %s OK\n", DM_MSG_PREFIX, i, argv[i]);
    }

    /*
     * Fix #9 — route all special bio types through map() so DM never
     * falls back to sector-by-sector emulation for the whole device.
     *
     * Fix #9 — ti->max_io_len caps bio size; prevents read-ahead from
     * generating bios that need more bounce pages than MIN_POOL_PAGES.
     */
    ti->num_flush_bios        = 1;
    ti->num_discard_bios      = 1;
    ti->num_write_zeroes_bios = 1;
    ti->max_io_len            = XOR_MAX_IO_SECTORS;

    ti->private = ctx;

    pr_info("[%s] ctr: done in %llu µs  max_io_len=%u pool=%d pages\n",
            DM_MSG_PREFIX, ktime_to_us(ktime_sub(ktime_get(), t_start)),
            XOR_MAX_IO_SECTORS, MIN_POOL_PAGES);
    pr_info("[%s] ctr: verbose=1 → every bio logged with unique ID (no rate-limit)\n",
            DM_MSG_PREFIX);
    pr_info("[%s] ctr: check dmesg for 'bio#N MAP' without matching 'bio#N DECODE done'\n",
            DM_MSG_PREFIX);
    return 0;

bad_devs:
    while (--i >= 0) dm_put_device(ti, ctx->devs[i]);
    mempool_exit(&ctx->bounce_pool);
bad_bioset:
    bioset_exit(&ctx->bio_set);
bad_ctx:
    kfree(ctx);
    return r;
}

static void xor_split_dtr(struct dm_target *ti) {
    struct xor_split_ctx *ctx = ti->private;
    ktime_t t_start = ktime_get();
    int i;

    pr_info("[%s] dtr: draining workqueue...\n", DM_MSG_PREFIX);
    drain_workqueue(xor_decode_wq);

    for (i = 0; i < ctx->dev_count; i++) {
        pr_info("[%s] dtr: releasing device[%d]\n", DM_MSG_PREFIX, i);
        dm_put_device(ti, ctx->devs[i]);
    }
    mempool_exit(&ctx->bounce_pool);
    bioset_exit(&ctx->bio_set);
    kfree(ctx);

    pr_info("[%s] dtr: done in %llu µs\n",
            DM_MSG_PREFIX, ktime_to_us(ktime_sub(ktime_get(), t_start)));
}

static struct target_type xor_split_target = {
    .name    = "xor_split",
    .version = {1, 0, 0},
    .module  = THIS_MODULE,
    .ctr     = xor_split_ctr,
    .dtr     = xor_split_dtr,
    .map     = xor_split_map,
};

static int __init dm_xor_split_init(void) {
    int r;

    xor_decode_wq = alloc_workqueue("dm_xor_split_decode",
                                    WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
    if (!xor_decode_wq) {
        DMWARN("Failed to allocate decode workqueue");
        return -ENOMEM;
    }

    r = dm_register_target(&xor_split_target);
    if (r < 0) {
        DMWARN("Target registration failed: %d", r);
        destroy_workqueue(xor_decode_wq);
        return r;
    }

    pr_info("[%s] Module loaded. insmod with verbose=1 for full bio lifecycle logging.\n",
            DM_MSG_PREFIX);
    return 0;
}

static void __exit dm_xor_split_exit(void) {
    dm_unregister_target(&xor_split_target);
    destroy_workqueue(xor_decode_wq);
    pr_info("[%s] Module unloaded.\n", DM_MSG_PREFIX);
}

module_init(dm_xor_split_init);
module_exit(dm_xor_split_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR split device mapper");