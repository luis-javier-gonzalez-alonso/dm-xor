#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>

#define DM_MSG_PREFIX "dm_xor_split"
#define MAX_SPLIT_DEVICES 8

/* Context structure allocated per device-mapper instance */
struct xor_split_ctx {
    int dev_count;
    struct dm_dev *devs[MAX_SPLIT_DEVICES];
    struct bio_set bio_set;
};

/* Tracking tracking structure handling async multi-bio completions */
struct xor_io_tracker {
    struct xor_split_ctx *ctx;
    struct bio *orig_bio;
    atomic_t pending_bios;
    int bi_status;
    int dev_count;
    struct bio *cloned_bios[MAX_SPLIT_DEVICES];
};

/* Inline helper to perform element-wise XOR over whole block vectors */
static void xor_bio_buffers(struct bio *dst, struct bio *src) {
    struct bio_vec bv_dst, bv_src;
    struct bvec_iter iter_dst, iter_src;
    void *addr_dst, *addr_src;
    int i;

    iter_src = src->bi_iter;
    bio_for_each_segment(bv_dst, dst, iter_dst) {
        if (!iter_src.bi_size) break;
        bv_src = bio_iter_iovec(src, iter_src);

        addr_dst = kmap_local_page(bv_dst.bv_page) + bv_dst.bv_offset;
        addr_src = kmap_local_page(bv_src.bv_page) + bv_src.bv_offset;

        for (i = 0; i < bv_dst.bv_len; i++) {
            ((u8 *)addr_dst)[i] ^= ((u8 *)addr_src)[i];
        }

        kunmap_local(addr_src);
        kunmap_local(addr_dst);
        bio_advance_iter(src, &iter_src, bv_dst.bv_len);
    }
}

/* Completion handler that processes read combinations or write cleanups */
static void xor_split_end_io(struct bio *clone) {
    struct xor_io_tracker *tracker = clone->bi_private;
    int i;

    if (clone->bi_status) {
        tracker->bi_status = clone->bi_status;
    }

    /* Process logic when the very last physical disk read/write completes */
    if (atomic_dec_and_test(&tracker->pending_bios)) {
        struct bio *orig = tracker->orig_bio;

        if (bio_data_dir(orig) == READ && !tracker->bi_status) {
            /* Sequentially XOR data read from Disks 1..N-1 onto Disk 0 */
            for (i = 1; i < tracker->dev_count; i++) {
                xor_bio_buffers(tracker->cloned_bios[0], tracker->cloned_bios[i]);
            }
            /* Copy the fully reconstructed payload straight to host buffer */
            bio_copy_data(orig, tracker->cloned_bios[0]);
        }

        /* Clean up all allocated clone allocations and data segments */
        for (i = 0; i < tracker->dev_count; i++) {
            struct bio_vec *bv;
            struct bvec_iter_all iter;
            bio_for_each_segment_all(bv, tracker->cloned_bios[i], iter) {
                __free_page(bv->bv_page);
            }
            bio_put(tracker->cloned_bios[i]);
        }

        orig->bi_status = tracker->bi_status;
        bio_endio(orig);
        kfree(tracker);
    }
}

/* Main Map Function intercepting high level Virtual Device bios */
static int xor_split_map(struct dm_target *ti, struct bio *bio) {
    struct xor_split_ctx *ctx = ti->private;
    struct xor_io_tracker *tracker;
    int i;

    if (bio->bi_opf & REQ_PREFLUSH) {
        return DM_MAPIO_REMAPPED;
    }

    tracker = kmalloc(sizeof(struct xor_io_tracker), GFP_NOIO);
    if (!tracker) return DM_MAPIO_REQUEUE;

    tracker->ctx = ctx;
    tracker->orig_bio = bio;
    tracker->bi_status = 0;
    tracker->dev_count = ctx->dev_count;
    atomic_set(&tracker->pending_bios, ctx->dev_count);

    /* Allocate and separate out data buffers for all underlying drives */
    for (i = 0; i < ctx->dev_count; i++) {
        struct bio *clone;
        struct bio_vec bv;
        struct bvec_iter iter;

        clone = bio_alloc_clone(ctx->devs[i]->bdev, bio, GFP_NOIO, &ctx->bio_set);
        tracker->cloned_bios[i] = clone;
        clone->bi_private = tracker;
        clone->bi_end_io = xor_split_end_io;

        /* Allocate explicit standalone pages to store specific intermediate blocks */
        bio_for_each_segment(bv, clone, iter) {
            struct page *bounce_page = alloc_page(GFP_NOIO);
            if (!bounce_page) goto page_alloc_failed;

            bv.bv_page = bounce_page;
            bv.bv_offset = 0;
        }

        /* Populate data if the incoming request is a host WRITE operation */
        if (bio_data_dir(bio) == WRITE) {
            if (i < ctx->dev_count - 1) {
                /* Disks 1 to N-1 get filled with random noise */
                bio_for_each_segment(bv, clone, iter) {
                    void *addr = kmap_local_page(bv.bv_page);
                    get_random_bytes(addr, bv.bv_len);
                    kunmap_local(addr);
                }
            } else {
                /* The Final Disk N accumulates cleartext XORed with every random stream */
                bio_copy_data(clone, bio);
                for (int j = 0; j < ctx->dev_count - 1; j++) {
                    xor_bio_buffers(clone, tracker->cloned_bios[j]);
                }
            }
        }
    }

    /* Submit all sub-bios asynchronously to their target devices */
    for (i = 0; i < ctx->dev_count; i++) {
        submit_bio(tracker->cloned_bios[i]);
    }

    return DM_MAPIO_SUBMITTED;

page_alloc_failed:
    /* Basic failure unwind omitted here for scannability; production needs full loop cleanup */
    kfree(tracker);
    return DM_MAPIO_REQUEUE;
}

/* Device Mapper Constructor (.ctr) */
static int xor_split_ctr(struct dm_target *ti, unsigned int argc, char **argv) {
    struct xor_split_ctx *ctx;
    int i, r;

    if (argc < 2 || argc > MAX_SPLIT_DEVICES) {
        ti->error = "Invalid argument count. Provide between 2 and 8 raw target disks.";
        return -EINVAL;
    }

    ctx = kzalloc(sizeof(struct xor_split_ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;

    ctx->dev_count = argc;
    r = bioset_init(&ctx->bio_set, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (r) goto bad_ctx;

    for (i = 0; i < argc; i++) {
        r = dm_get_device(ti, argv[i], dm_table_get_mode(ti->table), &ctx->devs[i]);
        if (r) {
            ti->error = "Target disk path acquisition failure";
            goto bad_devs;
        }
    }

    ti->private = ctx;
    return 0;

bad_devs:
    while (--i >= 0) dm_put_device(ti, ctx->devs[i]);
    bioset_exit(&ctx->bio_set);
bad_ctx:
    kfree(ctx);
    return r;
}

/* Device Mapper Destructor (.dtr) */
static void xor_split_dtr(struct dm_target *ti) {
    struct xor_split_ctx *ctx = ti->private;
    int i;

    for (i = 0; i < ctx->dev_count; i++) {
        dm_put_device(ti, ctx->devs[i]);
    }
    bioset_exit(&ctx->bio_set);
    kfree(ctx);
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
    int r = dm_register_target(&xor_split_target);
    if (r < 0) DMWARN("Target registration failed: %d", r);
    return r;
}

static void __exit dm_xor_split_exit(void) {
    dm_unregister_target(&xor_split_target);
}

module_init(dm_xor_split_init);
module_exit(dm_xor_split_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR split device mapper");
