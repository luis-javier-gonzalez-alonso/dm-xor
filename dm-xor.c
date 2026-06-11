// SPDX-License-Identifier: GPL-2.0+

/*
 * dm-xor.c — Device-mapper target that XOR-splits data across N disks.
 *
 * DESIGN GOALS:
 *   1. Keyless Physical Distribution: Secret share data across N drives using XOR.
 *   2. Cryptographic Security: High-speed ChaCha20 noise streams per-bio.
 *   3. Forward Progress Guarantee: Uses kmem_cache and mempool_t for all IO structures.
 *   4. Zero context-switch decode: Inline kmap_local_page in softirq for reads.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/mempool.h>
#include <crypto/skcipher.h>
#include <crypto/algapi.h>
#include <linux/scatterlist.h>

#define DM_MSG_PREFIX      "dm_xor"
#define MAX_SPLIT_DEVICES  8

/*
 * Bioset pool size. Must be >= MAX_SPLIT_DEVICES so a single map() call
 * can allocate all clone bios from the emergency pool without deadlocking.
 */
#define XOR_BIO_POOL_SIZE  (MAX_SPLIT_DEVICES * 4)

/* 
 * We allocate enough pages to guarantee forward progress for a full size bio.
 * Max sectors = 256 pages. Across 8 devices = 2048 pages reserved (~8 MB).
 */
#define XOR_BOUNCE_POOL_SIZE (MAX_SPLIT_DEVICES * BIO_MAX_VECS)

static struct workqueue_struct *xor_wq;
static struct kmem_cache *xor_tracker_cache;

static bool verbose;
module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Log every map() call to dmesg");

struct xor_ctx {
	int dev_count;
	struct dm_dev *devs[MAX_SPLIT_DEVICES];
	struct bio_set bio_set;

	/* Cryptographic noise generation */
	struct crypto_sync_skcipher *tfm;
	atomic64_t iv_counter;

	/* Forward progress guarantees */
	mempool_t *tracker_pool;
	mempool_t *page_pool;
};

/*
 * Per-IO tracker
 */
struct saved_seg {
	struct page *page;
	unsigned int offset;
	unsigned int len;
};

struct xor_io_tracker {
	struct xor_ctx *ctx;
	struct bio *orig_bio;
	atomic_t pending;
	blk_status_t status;
	int dev_count;
	int n_segs;		
	struct work_struct work;

	/* Sized to accommodate BIO_MAX_VECS natively */
	struct saved_seg segs[BIO_MAX_VECS];
	struct page *bounce[MAX_SPLIT_DEVICES][BIO_MAX_VECS];

	struct bio *clones[MAX_SPLIT_DEVICES];
};

static void free_bounce_pages(struct xor_io_tracker *t)
{
	int d, s;

	for (d = 0; d < t->dev_count; d++) {
		for (s = 0; s < t->n_segs; s++) {
			if (t->bounce[d][s]) {
				mempool_free(t->bounce[d][s], t->ctx->page_pool);
				t->bounce[d][s] = NULL;
			}
		}
	}
}

static void free_clones(struct xor_io_tracker *t)
{
	int d;

	for (d = 0; d < t->dev_count; d++) {
		if (t->clones[d]) {
			bio_put(t->clones[d]);
			t->clones[d] = NULL;
		}
	}
}

static void complete_orig(struct xor_io_tracker *t)
{
	t->orig_bio->bi_status = t->status;
	bio_endio(t->orig_bio);
	mempool_free(t, t->ctx->tracker_pool);
}

/*
 * Generate cryptographically secure noise using ChaCha20 for a given chunk.
 */
static int generate_noise(struct xor_ctx *ctx, struct page *dest_page, unsigned int len)
{
	u64 nonce = atomic64_inc_return(&ctx->iv_counter);
	u8 iv[16] = {0};
	struct scatterlist sg_in, sg_out;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, ctx->tfm);
	int ret;

	/* Use atomic counter for IV to ensure perfect cryptographic isolation */
	memcpy(iv, &nonce, sizeof(nonce));

	skcipher_request_set_sync_tfm(req, ctx->tfm);

	sg_init_table(&sg_in, 1);
	sg_set_page(&sg_in, ZERO_PAGE(0), len, 0);

	sg_init_table(&sg_out, 1);
	sg_set_page(&sg_out, dest_page, len, 0);

	skcipher_request_set_crypt(req, &sg_in, &sg_out, len, iv);

	ret = crypto_skcipher_encrypt(req);
	skcipher_request_zero(req);
	return ret;
}

/* Write worker — XOR-encode then submit (process context) */
static void xor_write_worker(struct work_struct *work)
{
	struct xor_io_tracker *t = container_of(work, struct xor_io_tracker, work);
	int s, d;
	int last_disk = t->dev_count - 1;

	/* XOR-encode original data into bounce pages */
	for (s = 0; s < t->n_segs; s++) {
		void *src, *dest_buf;
		unsigned int len = t->segs[s].len;

		/* 1. Generate random noise for disks 0 to N-2 */
		for (d = 0; d < last_disk; d++) {
			if (generate_noise(t->ctx, t->bounce[d][s], len) != 0) {
				pr_err("[%s] crypto encrypt failed for noise\n", DM_MSG_PREFIX);
				t->status = BLK_STS_IOERR;
			}
		}

		src = kmap_local_page(t->segs[s].page) + t->segs[s].offset;
		dest_buf = kmap_local_page(t->bounce[last_disk][s]);

		/* 2. Copy source data into final parity disk buffer */
		memcpy(dest_buf, src, len);

		/* 3. XOR all noise streams into the final bounce page using crypto API */
		for (d = 0; d < last_disk; d++) {
			void *noise = kmap_local_page(t->bounce[d][s]);
			crypto_xor(dest_buf, noise, len);
			kunmap_local(noise);
		}

		kunmap_local(dest_buf);
		kunmap_local(src);
	}

	for (d = 0; d < t->dev_count; d++)
		submit_bio(t->clones[d]);
}

/* 
 * Inline decode — Runs in softirq context (no workqueue needed) 
 * Safe since Linux 5.11 due to kmap_local_page.
 */
static void decode_inline(struct xor_io_tracker *t)
{
	int s, d;

	for (s = 0; s < t->n_segs; s++) {
		void *dst;
		unsigned int len = t->segs[s].len;

		dst = kmap_local_page(t->segs[s].page) + t->segs[s].offset;

		/* Reconstruct the original data by XORing all chunks together */
		memset(dst, 0, len);

		for (d = 0; d < t->dev_count; d++) {
			void *src = kmap_local_page(t->bounce[d][s]);
			crypto_xor(dst, src, len);
			kunmap_local(src);
		}

		kunmap_local(dst);
	}
}

/* End-IO callback (may run in interrupt or softirq context) */
static void xor_end_io(struct bio *clone)
{
	struct xor_io_tracker *t = clone->bi_private;

	if (clone->bi_status != BLK_STS_OK)
		t->status = clone->bi_status;

	if (!atomic_dec_and_test(&t->pending))
		return; /* other clones still in flight */

	if (bio_data_dir(t->orig_bio) == READ &&
	    t->status == BLK_STS_OK &&
	    t->n_segs > 0) {
		/* Decode inline immediately */
		decode_inline(t);
	}

	/* Handles WRITE, FLUSH, DISCARD, WRITE_ZEROES, or error paths */
	free_bounce_pages(t);
	free_clones(t);
	complete_orig(t);
}

static int xor_map(struct dm_target *ti, struct bio *bio)
{
	struct xor_ctx *ctx = ti->private;
	struct xor_io_tracker *t;
	enum req_op op = bio_op(bio);
	bool needs_bounce;
	int d, s;

	if (bio->bi_opf & REQ_PREFLUSH) {
		if (!bio_sectors(bio)) {
			needs_bounce = false; 
		} else {
			bio->bi_opf &= ~REQ_PREFLUSH;
			needs_bounce = true; 
		}
	} else {
		needs_bounce = (op == REQ_OP_READ || op == REQ_OP_WRITE);
	}

	t = mempool_alloc(ctx->tracker_pool, GFP_NOIO);
	if (!t)
		return DM_MAPIO_REQUEUE;

	t->ctx = ctx;
	t->orig_bio = bio;
	t->status = BLK_STS_OK;
	t->dev_count = ctx->dev_count;
	t->n_segs = 0;
	memset(t->bounce, 0, sizeof(t->bounce));
	memset(t->clones, 0, sizeof(t->clones));
	atomic_set(&t->pending, ctx->dev_count);

	if (verbose)
		pr_info("[%s] map: op=%u sector=%llu size=%u bounce=%d\n",
			DM_MSG_PREFIX, (__force unsigned) op,
			(unsigned long long)bio->bi_iter.bi_sector,
			bio->bi_iter.bi_size, (int)needs_bounce);

	/* Step 1: Snapshot segment table from original bio. */
	if (needs_bounce) {
		struct bio_vec bv;
		struct bvec_iter iter;

		bio_for_each_segment(bv, bio, iter) {
			if (t->n_segs >= BIO_MAX_VECS) {
				pr_err("[%s] bio too many segments (%d >= %d)\n",
				       DM_MSG_PREFIX, t->n_segs, BIO_MAX_VECS);
				mempool_free(t, ctx->tracker_pool);
				return DM_MAPIO_REQUEUE;
			}
			t->segs[t->n_segs].page = bv.bv_page;
			t->segs[t->n_segs].offset = bv.bv_offset;
			t->segs[t->n_segs].len = bv.bv_len;
			t->n_segs++;
		}
	}

	/* Step 2: Allocate bounce pages using mempool */
	if (needs_bounce) {
		for (d = 0; d < ctx->dev_count; d++) {
			for (s = 0; s < t->n_segs; s++) {
				t->bounce[d][s] = mempool_alloc(ctx->page_pool, GFP_NOIO);
				if (!t->bounce[d][s])
					goto fail;
			}
		}
	}

	/* Step 3: Build clone bios */
	for (d = 0; d < ctx->dev_count; d++) {
		struct bio *clone;
		int nr_vecs = needs_bounce ? t->n_segs : 0;

		clone = bio_alloc_bioset(ctx->devs[d]->bdev, nr_vecs,
					 bio->bi_opf, GFP_NOIO, &ctx->bio_set);
		if (!clone)
			goto fail;

		t->clones[d] = clone;
		clone->bi_private = t;
		clone->bi_end_io = xor_end_io;
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

	/* Step 4: Encode and submit (writes) or submit directly (reads/thin) */
	if (needs_bounce && bio_data_dir(bio) == WRITE) {
		INIT_WORK(&t->work, xor_write_worker);
		queue_work(xor_wq, &t->work);
	} else {
		for (d = 0; d < ctx->dev_count; d++)
			submit_bio(t->clones[d]);
	}

	return DM_MAPIO_SUBMITTED;

fail:
	free_clones(t);
	free_bounce_pages(t);
	mempool_free(t, ctx->tracker_pool);
	return DM_MAPIO_REQUEUE;
}

static int xor_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct xor_ctx *ctx;
	int i, r;
	u8 key[32];

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

	/* Initialize memory pools for forward progress */
	ctx->tracker_pool = mempool_create_slab_pool(XOR_BIO_POOL_SIZE, xor_tracker_cache);
	if (!ctx->tracker_pool) {
		ti->error = "Cannot create tracker mempool";
		r = -ENOMEM;
		goto bad_bioset;
	}

	ctx->page_pool = mempool_create_page_pool(XOR_BOUNCE_POOL_SIZE, 0);
	if (!ctx->page_pool) {
		ti->error = "Cannot create bounce page mempool";
		r = -ENOMEM;
		goto bad_tracker_pool;
	}

	/* Initialize ChaCha20 cipher */
	ctx->tfm = crypto_alloc_sync_skcipher("chacha20", 0, 0);
	if (IS_ERR(ctx->tfm)) {
		ti->error = "Cannot allocate chacha20 tfm";
		r = PTR_ERR(ctx->tfm);
		goto bad_page_pool;
	}

	get_random_bytes(key, sizeof(key));
	r = crypto_sync_skcipher_setkey(ctx->tfm, key, sizeof(key));
	if (r) {
		ti->error = "Cannot set chacha20 key";
		goto bad_tfm;
	}
	atomic64_set(&ctx->iv_counter, 0);

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

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_zeroes_bios = 1;

	ti->private = ctx;
	pr_info("[%s] ctr: %d devices ready\n", DM_MSG_PREFIX, argc);
	return 0;

bad_devs:
	while (--i >= 0)
		dm_put_device(ti, ctx->devs[i]);
bad_tfm:
	crypto_free_sync_skcipher(ctx->tfm);
bad_page_pool:
	mempool_destroy(ctx->page_pool);
bad_tracker_pool:
	mempool_destroy(ctx->tracker_pool);
bad_bioset:
	bioset_exit(&ctx->bio_set);
bad_ctx:
	kfree(ctx);
	return r;
}

static void xor_status(struct dm_target *ti, status_type_t type,
		       unsigned int status_flags, char *result,
		       unsigned int maxlen)
{
	struct xor_ctx *ctx = ti->private;
	int i;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		for (i = 0; i < ctx->dev_count; i++)
			DMEMIT("%s%s", i ? " " : "", ctx->devs[i]->name);
		break;
	case STATUSTYPE_IMA:
		result[0] = '\0';
		break;
	}
}

static int xor_iterate_devices(struct dm_target *ti,
			       iterate_devices_callout_fn fn, void *data)
{
	struct xor_ctx *ctx = ti->private;
	int ret = 0;
	int i;

	for (i = 0; !ret && i < ctx->dev_count; i++)
		ret = fn(ti, ctx->devs[i], 0, ti->len, data);

	return ret;
}

static void xor_dtr(struct dm_target *ti)
{
	struct xor_ctx *ctx = ti->private;
	int i;

	drain_workqueue(xor_wq);

	for (i = 0; i < ctx->dev_count; i++)
		dm_put_device(ti, ctx->devs[i]);

	crypto_free_sync_skcipher(ctx->tfm);
	mempool_destroy(ctx->page_pool);
	mempool_destroy(ctx->tracker_pool);
	bioset_exit(&ctx->bio_set);
	kfree(ctx);

	pr_info("[%s] dtr: done\n", DM_MSG_PREFIX);
}

static struct target_type xor_target = {
	.name            = "xor",
	.version         = { 1, 4, 0 },
	.module          = THIS_MODULE,
	.ctr             = xor_ctr,
	.dtr             = xor_dtr,
	.map             = xor_map,
	.status          = xor_status,
	.iterate_devices = xor_iterate_devices,
};

static int __init dm_xor_init(void)
{
	int r;

	xor_tracker_cache = kmem_cache_create("dm_xor_tracker",
					      sizeof(struct xor_io_tracker),
					      0, 0, NULL);
	if (!xor_tracker_cache)
		return -ENOMEM;

	xor_wq = alloc_workqueue("dm_xor", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!xor_wq) {
		r = -ENOMEM;
		goto destroy_cache;
	}

	r = dm_register_target(&xor_target);
	if (r < 0)
		goto destroy_wq;

	pr_info("[%s] loaded\n", DM_MSG_PREFIX);
	return 0;

destroy_wq:
	destroy_workqueue(xor_wq);
destroy_cache:
	kmem_cache_destroy(xor_tracker_cache);
	return r;
}

static void __exit dm_xor_exit(void)
{
	dm_unregister_target(&xor_target);
	destroy_workqueue(xor_wq);
	kmem_cache_destroy(xor_tracker_cache);
	pr_info("[%s] unloaded\n", DM_MSG_PREFIX);
}

module_init(dm_xor_init);
module_exit(dm_xor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Multi-disk XOR secret sharing device mapper");
MODULE_ALIAS("dm-xor");
