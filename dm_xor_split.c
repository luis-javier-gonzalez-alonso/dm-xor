#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>

/* Include our newly decoupled core logic */
#include "xor_core.h"

#define DM_MSG_PREFIX "dm_xor_split"
#define MAX_SPLIT_DEVICES 8

struct xor_split_ctx {
    int dev_count;
    struct dm_dev *devs[MAX_SPLIT_DEVICES];
    struct bio_set bio_set;
};

struct xor_io_tracker {
    struct xor_split_ctx *ctx;
    struct bio *orig_bio;
    atomic_t pending_bios;
    int bi_status;
    int dev_count;
    struct bio *cloned_bios[MAX_SPLIT_DEVICES];
};

/* Wrapper to adapt the kernel's get_random_bytes to our pure C abstraction */
static void kernel_random_wrapper(void *buf, size_t nbytes) {
    get_random_bytes(buf, (int)nbytes);
}

static void xor_split_end_io(struct bio *clone) {
    struct xor_io_tracker *tracker = clone->bi_private;
    struct bio *orig = tracker->orig_bio;
    int i;

    if (clone->bi_status != BLK_STS_OK) {
        tracker->bi_status = clone->bi_status;
    }

    if (atomic_dec_and_test(&tracker->pending_bios)) {
        if (bio_data_dir(orig) == READ && tracker->bi_status == BLK_STS_OK) {
            struct bio_vec bv_dst;
            struct bvec_iter iter_dst;
            int seg_idx = 0;

            /* Decode Phase: Read chunks from all clones and reconstruct directly into the original bio */
            bio_for_each_segment(bv_dst, orig, iter_dst) {
                uint8_t *mapped_srcs[MAX_SPLIT_DEVICES];
                void *dst_page_addr = kmap_local_page(bv_dst.bv_page) + bv_dst.bv_offset;
                int disk_idx;

                /* Map all hardware source pages */
                for (disk_idx = 0; disk_idx < tracker->dev_count; disk_idx++) {
                    struct bio *clone_bio = tracker->cloned_bios[disk_idx];
                    struct bio_vec *bv_src = &clone_bio->bi_io_vec[seg_idx];
                    mapped_srcs[disk_idx] = kmap_local_page(bv_src->bv_page);
                }

                /* Execute decoupled math logic */
                xor_split_decode(mapped_srcs, dst_page_addr, tracker->dev_count, bv_dst.bv_len);

                /* Safely unmap in reverse order */
                for (disk_idx = tracker->dev_count - 1; disk_idx >= 0; disk_idx--) {
                    kunmap_local(mapped_srcs[disk_idx]);
                }
                kunmap_local(dst_page_addr);
                seg_idx++;
            }
        }

        /* Clean up bounce allocations */
        for (i = 0; i < tracker->dev_count; i++) {
            struct bio_vec bv;
            struct bvec_iter iter;
            if (!tracker->cloned_bios[i]) continue;

            bio_for_each_segment(bv, tracker->cloned_bios[i], iter) {
                if (bv.bv_page) __free_page(bv.bv_page);
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
    int i, j;
    int is_write = (bio_data_dir(bio) == WRITE);

    if (bio->bi_opf & REQ_PREFLUSH) {
        return DM_MAPIO_REMAPPED;
    }

    tracker = kzalloc(sizeof(struct xor_io_tracker), GFP_NOIO);
    if (!tracker) return DM_MAPIO_REQUEUE;

    tracker->ctx = ctx;
    tracker->orig_bio = bio;
    tracker->bi_status = 0;
    tracker->dev_count = ctx->dev_count;
    atomic_set(&tracker->pending_bios, ctx->dev_count);

    /* PHASE 1: Allocate matching sub-bios using exact segment sizes */
    for (i = 0; i < ctx->dev_count; i++) {
        struct bio *clone;
        struct bio_vec bv;
        struct bvec_iter iter;

        clone = bio_alloc_bioset(ctx->devs[i]->bdev, bio_segments(bio),
                                 bio->bi_opf, GFP_NOIO, &ctx->bio_set);
        if (!clone) goto allocation_failed;

        clone->bi_iter.bi_sector = bio->bi_iter.bi_sector;
        tracker->cloned_bios[i] = clone;
        clone->bi_private = tracker;
        clone->bi_end_io = xor_split_end_io;

        /* Provision dedicated independent bounce layers */
        bio_for_each_segment(bv, bio, iter) {
            struct page *bounce_page = alloc_page(GFP_NOIO);
            if (!bounce_page) goto allocation_failed;

            if (bio_add_page(clone, bounce_page, bv.bv_len, 0) < bv.bv_len) {
                pr_err("[%s] Safeguard: bio_add_page failed\n", DM_MSG_PREFIX);
                __free_page(bounce_page);
                goto allocation_failed;
            }
        }
    }

    /* PHASE 2: Encode Data Split Matrix via Core Library */
    if (is_write) {
        int seg_idx = 0;
        struct bio_vec bv_src;
        struct bvec_iter iter_src;

        bio_for_each_segment(bv_src, bio, iter_src) {
            uint8_t *mapped_addrs[MAX_SPLIT_DEVICES];
            void *src_addr = kmap_local_page(bv_src.bv_page) + bv_src.bv_offset;
            int disk_idx;

            /* Map destination bounce pages */
            for (disk_idx = 0; disk_idx < ctx->dev_count; disk_idx++) {
                struct bio *clone = tracker->cloned_bios[disk_idx];
                struct bio_vec *bv_dst = &clone->bi_io_vec[seg_idx];
                mapped_addrs[disk_idx] = kmap_local_page(bv_dst->bv_page);
            }

            /* Execute decoupled math logic injected with the kernel's random generator */
            xor_split_encode(src_addr, mapped_addrs, ctx->dev_count, bv_src.bv_len, kernel_random_wrapper);

            /* Safely unmap */
            for (disk_idx = ctx->dev_count - 1; disk_idx >= 0; disk_idx--) {
                kunmap_local(mapped_addrs[disk_idx]);
            }
            kunmap_local(src_addr);
            seg_idx++;
        }
    }

    /* PHASE 3: Non-blocking, Asynchronous Submission Queueing */
    for (i = 0; i < ctx->dev_count; i++) {
        submit_bio(tracker->cloned_bios[i]);
    }

    return DM_MAPIO_SUBMITTED;

allocation_failed:
    for (j = 0; j < ctx->dev_count; j++) {
        struct bio_vec bv;
        struct bvec_iter iter;
        if (!tracker->cloned_bios[j]) continue;

        bio_for_each_segment(bv, tracker->cloned_bios[j], iter) {
            if (bv.bv_page) __free_page(bv.bv_page);
        }
        bio_put(tracker->cloned_bios[j]);
    }
    kfree(tracker);
    return DM_MAPIO_REQUEUE;
}

static int xor_split_ctr(struct dm_target *ti, unsigned int argc, char **argv) {
    struct xor_split_ctx *ctx;
    int i, r;

    pr_info("[%s] Initializing constructor instance\n", DM_MSG_PREFIX);

    if (argc < 2 || argc > MAX_SPLIT_DEVICES) {
        ti->error = "Invalid argument count. Provide between 2 and 8 raw target disks.";
        return -EINVAL;
    }

    ctx = kzalloc(sizeof(struct xor_split_ctx), GFP_KERNEL);
    if (!ctx) return -ENOMEM;

    ctx->dev_count = argc;
    r = bioset_init(&ctx->bio_set, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (r) {
        ti->error = "Bioset initialization failure";
        goto bad_ctx;
    }

    for (i = 0; i < argc; i++) {
        r = dm_get_device(ti, argv[i], dm_table_get_mode(ti->table), &ctx->devs[i]);
        if (r) {
            ti->error = "Target disk path acquisition failure";
            pr_err("[%s] Failed to grab backend device descriptor for target: %s\n", DM_MSG_PREFIX, argv[i]);
            goto bad_devs;
        }
        pr_info("[%s] Successfully attached physical device mapping: %s -> Index %d\n", DM_MSG_PREFIX, argv[i], i);
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

static void xor_split_dtr(struct dm_target *ti) {
    struct xor_split_ctx *ctx = ti->private;
    int i;

    pr_info("[%s] Destructor instance clean up invoked\n", DM_MSG_PREFIX);
    for (i = 0; i < ctx->dev_count; i++) {
        pr_info("[%s] Releasing block device descriptor tracking index %d\n", DM_MSG_PREFIX, i);
        dm_put_device(ti, ctx->devs[i]);
    }
    bioset_exit(&ctx->bio_set);
    kfree(ctx);
}

static struct target_type xor_split_target = {
    .name = "xor_split",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = xor_split_ctr,
    .dtr = xor_split_dtr,
    .map = xor_split_map,
};

static int __init dm_xor_split_init(void) {
    int r = dm_register_target(&xor_split_target);
    if (r < 0) {
        DMWARN("Target registration failed: %d", r);
    } else {
        pr_info("[%s] Custom XOR Multiplex Split Driver registered successfully.\n", DM_MSG_PREFIX);
    }
    return r;
}

static void __exit dm_xor_split_exit(void) {
    dm_unregister_target(&xor_split_target);
    pr_info("[%s] Custom XOR Multiplex Split Driver unregistered cleanly.\n", DM_MSG_PREFIX);
}

module_init(dm_xor_split_init);
module_exit(dm_xor_split_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR split device mapper");