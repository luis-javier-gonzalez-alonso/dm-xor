#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/mempool.h>   /* Fix #2: mempool_t for bounce pages */
#include <linux/workqueue.h> /* Fix #4 / Fix #5: workqueue for XOR decode deferral */

/* Include our newly decoupled core logic */
#include "xor_core.h"

#define DM_MSG_PREFIX "dm_xor_split"
#define MAX_SPLIT_DEVICES 8

/*
 * Fix #2: A dedicated mempool for bounce pages guarantees forward progress
 * under memory pressure.  The pool is backed by a page allocator directly
 * (using mempool_alloc_page / mempool_free_page helpers).
 * MIN_POOL_PAGES is tuned to hold one full set of per-disk bounce pages for
 * a reasonable number of concurrent I/Os; adjust as needed.
 */
#define MIN_POOL_PAGES 64

/*
 * Fix #5: Use a private, unbound workqueue with WQ_MEM_RECLAIM.
 *
 * WHY NOT system_wq:
 *   schedule_work() dispatches to system_wq, which is shared across the
 *   entire kernel (block layer, filesystems, loop device, memory reclaim…).
 *   Under pressure, all system_wq worker threads can be occupied by tasks that
 *   are themselves waiting for block I/O to complete.  Our xor_decode_worker
 *   would sit in the queue behind those tasks, never running, while dd holds
 *   an uninterruptible wait on bio_endio(orig) — classic D-state deadlock.
 *
 * WHY WQ_MEM_RECLAIM:
 *   This flag makes the workqueue infrastructure allocate a dedicated "rescue"
 *   thread that is guaranteed to always make forward progress, even when every
 *   CPU is saturated.  It is mandatory for any workqueue that sits in the I/O
 *   completion path (see Documentation/core-api/workqueue.rst).
 *
 * WHY WQ_UNBOUND:
 *   Lets the worker run on any CPU immediately, avoiding per-CPU queue latency.
 */
static struct workqueue_struct *xor_decode_wq;

struct xor_split_ctx {
    int dev_count;
    struct dm_dev *devs[MAX_SPLIT_DEVICES];
    struct bio_set bio_set;
    mempool_t bounce_pool; /* Fix #2: module-wide bounce page mempool */
};

struct xor_io_tracker {
    struct xor_split_ctx *ctx;
    struct bio *orig_bio;
    atomic_t pending_bios;
    /*
     * Fix #1: bi_status is written only via cmpxchg so that concurrent
     * end-io callbacks cannot silently overwrite each other's error codes.
     */
    blk_status_t bi_status;
    int dev_count;
    struct bio *cloned_bios[MAX_SPLIT_DEVICES];
    /* Fix #4 / #5: work item used to defer XOR decoding out of end-io context */
    struct work_struct decode_work;
};

/* Wrapper to adapt the kernel's get_random_bytes to our pure C abstraction */
static void kernel_random_wrapper(void *buf, size_t nbytes) {
    get_random_bytes(buf, (int)nbytes);
}

/* ---------------------------------------------------------------------------
 * Fix #4 / #5: XOR decode worker
 *
 * Runs in process context on xor_decode_wq (WQ_MEM_RECLAIM | WQ_UNBOUND),
 * so it is safe to perform heavy CPU work and is guaranteed to make forward
 * progress even under memory pressure or system_wq saturation.
 * --------------------------------------------------------------------------- */
static void xor_decode_worker(struct work_struct *work)
{
    struct xor_io_tracker *tracker =
        container_of(work, struct xor_io_tracker, decode_work);
    struct bio *orig = tracker->orig_bio;

    /* Decode Phase: read chunks from all clones and reconstruct into orig */
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

    /*
     * Clean up bounce allocations.
     *
     * Fix #3: After bio completion bi_iter.bi_size == 0, so bio_for_each_segment
     * would silently iterate zero times and leak every bounce page.  Use the
     * raw bvec table (bi_io_vec / bi_vcnt) to walk all vectors unconditionally.
     */
    {
        int i;
        for (i = 0; i < tracker->dev_count; i++) {
            struct bio *clone = tracker->cloned_bios[i];
            int v;
            if (!clone)
                continue;
            for (v = 0; v < clone->bi_vcnt; v++) {
                struct bio_vec *bv = &clone->bi_io_vec[v];
                if (bv->bv_page)
                    mempool_free(bv->bv_page, &tracker->ctx->bounce_pool);
            }
            bio_put(clone);
        }
    }

    orig->bi_status = tracker->bi_status;
    bio_endio(orig);
    kfree(tracker);
}

static void xor_split_end_io(struct bio *clone) {
    struct xor_io_tracker *tracker = clone->bi_private;
    struct bio *orig = tracker->orig_bio;

    /*
     * Fix #1: Use cmpxchg so that only the first error wins and concurrent
     * completions from different CPUs cannot race on tracker->bi_status.
     * cmpxchg(ptr, old, new) atomically stores 'new' only when *ptr == old.
     */
    if (clone->bi_status != BLK_STS_OK)
        cmpxchg(&tracker->bi_status, BLK_STS_OK, clone->bi_status);

    if (atomic_dec_and_test(&tracker->pending_bios)) {
        if (bio_data_dir(orig) == READ && tracker->bi_status == BLK_STS_OK) {
            /*
             * Fix #4 / #5: Defer the CPU-intensive XOR decode (and the
             * subsequent cleanup) to xor_decode_wq instead of doing it here
             * in the bio end-io callback (which may be softirq/hardirq context).
             *
             * queue_work() on our dedicated WQ_MEM_RECLAIM workqueue — NOT
             * schedule_work() on system_wq — guarantees the worker always runs
             * even when system_wq is saturated by other kernel subsystems.
             */
            INIT_WORK(&tracker->decode_work, xor_decode_worker);
            queue_work(xor_decode_wq, &tracker->decode_work);
            return; /* cleanup and bio_endio happen in the worker */
        }

        /*
         * Write path or error path: no XOR work needed, just free bounce
         * pages and complete the original bio.
         *
         * Fix #3: Walk the raw bvec table so we free pages even after the
         * bio iterator has been exhausted (bi_iter.bi_size == 0 after completion).
         */
        {
            int i;
            for (i = 0; i < tracker->dev_count; i++) {
                struct bio *c = tracker->cloned_bios[i];
                int v;
                if (!c)
                    continue;
                for (v = 0; v < c->bi_vcnt; v++) {
                    struct bio_vec *bv = &c->bi_io_vec[v];
                    if (bv->bv_page)
                        mempool_free(bv->bv_page, &tracker->ctx->bounce_pool);
                }
                bio_put(c);
            }
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
    tracker->bi_status = BLK_STS_OK;
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

        /*
         * Fix #2: Allocate bounce pages from the mempool instead of directly
         * from the page allocator.  mempool_alloc with GFP_NOIO will block
         * until a page is available from the pre-reserved pool rather than
         * returning NULL under memory pressure, guaranteeing forward progress.
         */
        bio_for_each_segment(bv, bio, iter) {
            struct page *bounce_page =
                mempool_alloc(&ctx->bounce_pool, GFP_NOIO);
            if (!bounce_page) goto allocation_failed;

            if (bio_add_page(clone, bounce_page, bv.bv_len, 0) < bv.bv_len) {
                pr_err("[%s] Safeguard: bio_add_page failed\n", DM_MSG_PREFIX);
                mempool_free(bounce_page, &ctx->bounce_pool);
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
            for (disk_idx = ctx->dev_count - 1; disk_idx >= 0; disk_idx--)
                kunmap_local(mapped_addrs[disk_idx]);
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
        struct bio *c = tracker->cloned_bios[j];
        int v;
        if (!c)
            continue;
        for (v = 0; v < c->bi_vcnt; v++) {
            struct bio_vec *bv = &c->bi_io_vec[v];
            if (bv->bv_page)
                mempool_free(bv->bv_page, &ctx->bounce_pool);
        }
        bio_put(c);
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

    /*
     * Fix #6: BIOSET_NEED_RESCUER is required for any DM target that allocates
     * bios from a set and defers their completion to a workqueue.
     *
     * Without it: bio_alloc_bioset() can block (mempool wait) on the 3rd+ read
     * if the pool is momentarily exhausted by in-flight clones whose bio_put()
     * has been deferred to xor_decode_wq.  If xor_decode_wq is itself stalled
     * (e.g. behind another task waiting for block I/O), nobody calls bio_put(),
     * nobody replenishes the pool, and bio_alloc_bioset() waits forever
     * → D-state deadlock.
     *
     * BIOSET_NEED_RESCUER creates a dedicated rescue thread inside the bio_set
     * that can service pending bios and release pool elements back under exactly
     * these conditions, breaking the dependency cycle and guaranteeing progress.
     */
    r = bioset_init(&ctx->bio_set, BIO_POOL_SIZE, 0,
                    BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r) {
        ti->error = "Bioset initialization failure";
        goto bad_ctx;
    }

    /*
     * Fix #2: Initialize the bounce page mempool.  mempool_init_page_pool
     * uses the page allocator as the backing store, pre-reserves MIN_POOL_PAGES
     * pages at setup time so they are always available for I/O even under
     * heavy memory pressure.
     */
    r = mempool_init_page_pool(&ctx->bounce_pool, MIN_POOL_PAGES, 0);
    if (r) {
        ti->error = "Bounce page mempool initialization failure";
        goto bad_bioset;
    }

    for (i = 0; i < argc; i++) {
        r = dm_get_device(ti, argv[i], dm_table_get_mode(ti->table), &ctx->devs[i]);
        if (r) {
            ti->error = "Target disk path acquisition failure";
            pr_err("[%s] Failed to grab backend device descriptor for target: %s\n",
                   DM_MSG_PREFIX, argv[i]);
            goto bad_devs;
        }
        pr_info("[%s] Successfully attached physical device mapping: %s -> Index %d\n",
                DM_MSG_PREFIX, argv[i], i);
    }

    ti->private = ctx;
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
    int i;

    pr_info("[%s] Destructor instance clean up invoked\n", DM_MSG_PREFIX);

    /*
     * Fix #5 (teardown safety): Drain xor_decode_wq before freeing the context.
     *
     * The DM layer guarantees that no NEW bios will be mapped after dtr() is
     * called, but a previously-scheduled xor_decode_worker may still be running
     * or queued.  That worker dereferences tracker->ctx (our bounce_pool) after
     * the last bio_endio() call.  If we free ctx before the worker finishes, we
     * get a use-after-free.  drain_workqueue() blocks until all pending items on
     * xor_decode_wq have completed.
     */
    drain_workqueue(xor_decode_wq);

    for (i = 0; i < ctx->dev_count; i++) {
        pr_info("[%s] Releasing block device descriptor tracking index %d\n",
                DM_MSG_PREFIX, i);
        dm_put_device(ti, ctx->devs[i]);
    }
    mempool_exit(&ctx->bounce_pool);
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
    int r;

    /*
     * Fix #5: Create the module-wide decode workqueue.
     *
     * Flags:
     *   WQ_MEM_RECLAIM – guarantees a rescue thread for forward progress in
     *                    the I/O completion path, even under memory pressure.
     *   WQ_UNBOUND     – workers are not pinned to a CPU; allows immediate
     *                    dispatch on any idle core.
     * max_active = 0 means "use the system default" (no artificial concurrency cap).
     */
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

    pr_info("[%s] Custom XOR Multiplex Split Driver registered successfully.\n",
            DM_MSG_PREFIX);
    return 0;
}

static void __exit dm_xor_split_exit(void) {
    dm_unregister_target(&xor_split_target);
    destroy_workqueue(xor_decode_wq);
    pr_info("[%s] Custom XOR Multiplex Split Driver unregistered cleanly.\n",
            DM_MSG_PREFIX);
}

module_init(dm_xor_split_init);
module_exit(dm_xor_split_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR split device mapper");