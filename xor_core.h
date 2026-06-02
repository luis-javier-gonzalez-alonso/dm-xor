#ifndef XOR_CORE_H
#define XOR_CORE_H

/* * Environment detection:
 * The kernel build system defines __KERNEL__.
 * If it's defined, use kernel headers. Otherwise, use user-space stdlib.
 */
#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stddef.h>
    #include <stdint.h>
#endif

/* Function pointer to allow injecting mock random generators in tests,
   or get_random_bytes in the kernel. */
typedef void (*random_bytes_cb)(void *buf, size_t nbytes);

/* Encodes a source buffer into N destination buffers */
void xor_split_encode(const uint8_t *src, uint8_t **dest_buffers, int num_devices, size_t length,
                      random_bytes_cb rand_fn);

/* Decodes N source buffers back into one destination buffer */
void xor_split_decode(uint8_t **src_buffers, uint8_t *dest, int num_devices, size_t length);

#endif
