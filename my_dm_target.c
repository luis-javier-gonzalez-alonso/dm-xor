#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device-mapper.h>

MODULE_LICENSE("GPL");

static int __init my_init(void) {
    pr_info("Hello from M4 Mac environment!\n");
    return 0;
}

static void __exit my_exit(void) {
    pr_info("Goodbye!\n");
}

module_init(my_init);
module_exit(my_exit);

