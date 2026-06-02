#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "xor_core.h"

#define MAX_DEVICES 8

/* Mock random generator for user-space testing */
static void mock_random_bytes(void *buf, size_t nbytes) {
    if (nbytes == 0) return;
    uint8_t *ptr = (uint8_t *)buf;
    for (size_t i = 0; i < nbytes; i++) {
        ptr[i] = rand() % 256;
    }
}

/* Helper function to allocate buffers for tests */
static void allocate_buffers(uint8_t **buffers, int num_devices, size_t len) {
    for (int i = 0; i < num_devices; i++) {
        buffers[i] = calloc(1, len > 0 ? len : 1); /* calloc 1 byte if length is 0 to avoid malloc(0) edge cases */
    }
}

/* Helper function to free buffers */
static void free_buffers(uint8_t **buffers, int num_devices) {
    for (int i = 0; i < num_devices; i++) {
        free(buffers[i]);
    }
}

/* -------------------------------------------------------------------------- */
/* TEST SUITE                                                                 */
/* -------------------------------------------------------------------------- */

static void test_garbage_and_isolation() {
    int num_devices = 4;
    size_t len = 64;
    uint8_t src[64] = "SECRET_DATA_DO_NOT_LEAK_IN_PLAINTEXT_ON_ANY_SINGLE_DRIVE_000000";
    uint8_t zero_buffer[64] = {0};
    uint8_t *disk_buffers[MAX_DEVICES];

    allocate_buffers(disk_buffers, num_devices, len);
    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);

    /* Verify data is "garbage" on every individual stream */
    for (int i = 0; i < num_devices; i++) {
        /* 1. Ensure no single disk contains the plaintext */
        assert(memcmp(src, disk_buffers[i], len) != 0);

        /* 2. Ensure the disk is not just full of zeros (must have entropy/data) */
        assert(memcmp(zero_buffer, disk_buffers[i], len) != 0);
    }

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Data obfuscation and garbage verification successful.\n");
}

static void test_idempotency() {
    int num_devices = 3;
    size_t len = 32;
    uint8_t src[32] = "Idempotency_Test_Payload_123456";
    uint8_t *disk_buffers[MAX_DEVICES];
    uint8_t dest1[32] = {0};
    uint8_t dest2[32] = {0};

    allocate_buffers(disk_buffers, num_devices, len);

    /* Write Phase */
    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);

    /* Read Phase 1 */
    xor_split_decode(disk_buffers, dest1, num_devices, len);

    /* Read Phase 2 (Idempotent operation on the same disk buffers) */
    xor_split_decode(disk_buffers, dest2, num_devices, len);

    /* Verify both reads are identical to the source and to each other */
    assert(memcmp(src, dest1, len) == 0);
    assert(memcmp(src, dest2, len) == 0);
    assert(memcmp(dest1, dest2, len) == 0);

    /* Verify the source disks were NOT mutated during the decode phase */
    uint8_t dest3[32] = {0};
    xor_split_decode(disk_buffers, dest3, num_devices, len);
    assert(memcmp(dest1, dest3, len) == 0);

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Decode idempotency verified.\n");
}

static void test_minimum_devices() {
    int num_devices = 2; /* Smallest possible XOR split */
    size_t len = 16;
    uint8_t src[16] = "Min_Devices_Test";
    uint8_t *disk_buffers[MAX_DEVICES];
    uint8_t dest[16] = {0};

    allocate_buffers(disk_buffers, num_devices, len);

    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);
    xor_split_decode(disk_buffers, dest, num_devices, len);

    assert(memcmp(src, dest, len) == 0);

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Edge Case: Minimum devices (2) successful.\n");
}

static void test_unaligned_lengths() {
    int num_devices = 5;
    size_t len = 17; /* Prime number, unaligned to 32/64-bit boundaries */
    uint8_t src[17] = "Unaligned_Data!!";
    uint8_t *disk_buffers[MAX_DEVICES];
    uint8_t dest[17] = {0};

    allocate_buffers(disk_buffers, num_devices, len);

    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);
    xor_split_decode(disk_buffers, dest, num_devices, len);

    assert(memcmp(src, dest, len) == 0);

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Edge Case: Unaligned block lengths successful.\n");
}

static void test_zero_length() {
    int num_devices = 4;
    size_t len = 0;
    uint8_t src[1] = {0xFF};
    uint8_t *disk_buffers[MAX_DEVICES];
    uint8_t dest[1] = {0x00};

    allocate_buffers(disk_buffers, num_devices, len);

    /* Should not crash, infinite loop, or write anything */
    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);
    xor_split_decode(disk_buffers, dest, num_devices, len);

    /* Dest should remain untouched */
    assert(dest[0] == 0x00);

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Edge Case: Zero-length buffer handling successful.\n");
}

static void test_data_corruption() {
    int num_devices = 3;
    size_t len = 16;
    uint8_t src[16] = "Fragile_Data_Set";
    uint8_t *disk_buffers[MAX_DEVICES];
    uint8_t dest[16] = {0};

    allocate_buffers(disk_buffers, num_devices, len);

    xor_split_encode(src, disk_buffers, num_devices, len, mock_random_bytes);

    /* Simulate silent bit-rot / sector corruption on Disk 1 */
    disk_buffers[1][5] ^= 0xFF;

    xor_split_decode(disk_buffers, dest, num_devices, len);

    /* The decode MUST fail to match the source because XOR splits lack parity/FEC */
    assert(memcmp(src, dest, len) != 0);

    free_buffers(disk_buffers, num_devices);
    printf("[PASS] Fault Tolerance: Confirmed data corruption cascades as expected.\n");
}

int main() {
    printf("======================================\n");
    printf("Running XOR Core Split Test Suite\n");
    printf("======================================\n");

    /* Seed the mock random generator */
    srand(42);

    test_garbage_and_isolation();
    test_idempotency();
    test_minimum_devices();
    test_unaligned_lengths();
    test_zero_length();
    test_data_corruption();

    printf("======================================\n");
    printf("All Tests Passed.\n");
    printf("======================================\n");
    return 0;
}