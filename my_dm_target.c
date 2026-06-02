#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

// This structure holds the information for the target instances (2 for now) TODO extend to N
struct xor_dm_target_context {
    struct dm_dev *dev1;
    struct dm_dev *dev2;
};

// 1. The Constructor: Called when you create the device via 'dmsetup'
static int xor_dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct xor_dm_target_context *ctx;

    if (argc < 2) {
        ti->error = "Invalid argument count. Need 2 underlying devices.";
        return -EINVAL;
    }

    ctx = kmalloc(sizeof(struct my_dm_target_context), GFP_KERNEL);
    if (!ctx) return -ENOMEM;

    // Open the underlying block devices
    if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &ctx->dev1)) {
        ti->error = "Cannot open first device";
        kfree(ctx);
        return -EINVAL;
    }
    if (dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &ctx->dev2)) {
        ti->error = "Cannot open second device";
        kfree(ctx);
        return -EINVAL;
    }

    ti->private = ctx;
    return 0;
}

// 2. The Map Function: This is where the magic happens for READ/WRITE
static int xor_dm_map(struct dm_target *ti, struct bio *bio)
{
    struct my_dm_target_context *ctx = ti->private;

    // Point the incoming I/O to our primary physical device
    bio_set_dev(bio, ctx->dev1->bdev);

    if (bio_data_dir(bio) == WRITE) {
        // FOR LEARNING RAID:
        // You would eventually clone this 'bio' using bio_clone_fast()
        // and send the clone to ctx->dev2->bdev.
        pr_info("Intercepted a WRITE request!\n");
    } else {
        pr_info("Intercepted a READ request!\n");
    }

    // Remap and let the kernel handle the rest
    return DM_MAPIO_REMAPPED;
}

// 3. The Destructor: Called when the device is torn down
static void xor_dm_dtr(struct dm_target *ti)
{
    struct my_dm_target_context *ctx = ti->private;
    dm_put_device(ti, ctx->dev1);
    dm_put_device(ti, ctx->dev2);
    kfree(ctx);
}

static struct target_type xor_device_mapper_target = {
    .name    = "xor_device_mapper",
    .version = {1, 0, 0},
    .module  = THIS_MODULE,
    .ctr     = xor_dm_ctr,
    .map     = xor_dm_map,
    .dtr     = xor_dm_dtr,
};

static int __init xor_device_mapper_module_init(void) {
    return dm_register_target(&xor_device_mapper_target);
}

static void __exit xor_device_mapper_module_exit(void) {
    dm_unregister_target(&xor_device_mapper_target);
}

MODULE_LICENSE("GPL");

module_init(xor_device_mapper_module_init);
module_exit(xor_device_mapper_module_exit);
