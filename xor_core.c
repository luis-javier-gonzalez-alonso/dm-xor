#include "xor_core.h"

void xor_encode(const uint8_t *src, uint8_t **dest_buffers, int num_devices, size_t length,
                      random_bytes_cb rand_fn) {
    int last_disk = num_devices - 1;
    size_t b;
    int i;

    /* Generate random noise for the first N-1 disks */
    for (i = 0; i < last_disk; i++) {
        rand_fn(dest_buffers[i], length);
    }

    /* Compute the XOR matrix for the final disk */
    for (b = 0; b < length; b++) {
        uint8_t val = src[b];
        for (i = 0; i < last_disk; i++) {
            val ^= dest_buffers[i][b];
        }
        dest_buffers[last_disk][b] = val;
    }
}

void xor_decode(uint8_t **src_buffers, uint8_t *dest, int num_devices, size_t length) {
    size_t b;
    int i;

    /* Reconstruct the original data by XORing all chunks together */
    for (b = 0; b < length; b++) {
        uint8_t val = 0;
        for (i = 0; i < num_devices; i++) {
            val ^= src_buffers[i][b];
        }
        dest[b] = val;
    }
}
