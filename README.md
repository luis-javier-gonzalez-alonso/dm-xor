# dm-xor

Device-Mapper's "xor" target splits and secret-shares data across multiple underlying block devices (between 2 and 8). Instead of relying on a central encryption key, it ensures data confidentiality by using a ChaCha20 keystream to generate cryptographic noise, XORing the payload across all configured drives.

## Architecture & Guarantees

* **Zero context-switch decode:** Read operations are decoded inline within the softirq context using `kmap_local_page()`, providing extremely low latency.
* **Async Write Offloading:** Write operations are offloaded to a dedicated workqueue. This prevents block XORing operations from stalling the submitter thread.
* **Forward Progress:** Pre-allocated `kmem_cache` and `mempool_t` are used for all I/O tracking structures and bounce pages, guaranteeing forward progress and preventing out-of-memory (OOM) conditions under heavy I/O load.
* **Cryptographic Isolation:** An atomic IV counter ensures non-repeating nonces per segment for the ChaCha20 cipher, providing strong cryptographic isolation without depleting the kernel entropy pool.
* **Strict Metadata Hiding:** `dm-xor` intentionally drops `DISCARD` and hardware `WRITE_ZEROES` commands. This ensures that zeroed blocks and free filesystem space are securely overwritten with cryptographic noise rather than physically unmapped or zeroed out, maintaining true plausible deniability by preventing attackers from analyzing disk usage patterns.

## Parameters

```text
<dev1> <dev2> [<dev3> ... <dev8>]
```

* `<dev>`: Full pathname to the underlying block-device, or a "major:minor" device-number. The target requires a minimum of 2 devices and supports a maximum of 8.

## Example Usage

Create a 3-way split XOR device from three identical block devices:

```sh
#!/bin/sh
# Split data across 3 underlying devices

# Get the size in sectors of the first device
size=`blockdev --getsz $1`

# Create the device-mapper target
dmsetup create my_xor_device --table "0 $size xor $1 $2 $3"
```

You can then format and mount the resulting device `/dev/mapper/my_xor_device`.

### Initialization (Secure Setup)

To achieve the best security and ensure plausible deniability, the disks must be fully populated with random noise *before* you use them. If you simply create an ext4 filesystem on a fresh set of SSDs, the majority of the sectors will remain as physically distinguishable zeroes.

To prevent this, it is highly recommended to wipe the entire virtual device with zeroes (which `dm-xor` will securely encrypt into random noise) *before* formatting:

```sh
# This writes encrypted zeroes across all underlying disks
dd if=/dev/zero of=/dev/mapper/my_xor_device bs=4M status=progress
```

After this command completes, your physical drives will be completely filled with indistinguishable cryptographic noise. You can then safely format and mount the device.

### Best Practices: Secure Deletion

Because `dm-xor` intentionally drops `DISCARD` (TRIM) operations to prevent metadata leakage, deleting a file via standard `rm` simply marks its blocks as free in the filesystem, leaving the encrypted plaintext on disk until overwritten.

To permanently destroy sensitive files and prevent recovery if the entire array is ever fully compromised, securely overwrite them with random or zero data **before** deletion. The `shred` utility is recommended for this:

```sh
shred -u /path/to/sensitive/file
```
Since `dm-xor` handles all zero-writes securely, the `shred` command will overwrite the file with fresh, indistinguishable ChaCha20 noise across all disks.

## Installation Mechanisms

The preferred way to install `dm-xor` is by using the pre-built packages available in the GitHub repository's Releases section. We provide `.deb`, `.rpm`, and Arch Linux packages. If a package is not available for your distribution, you should fall back to using DKMS or building it manually.

### Packaged Releases (Preferred)

Check the GitHub Releases page to download the package corresponding to your distribution. Installing via the package manager ensures dependencies are met and the module is integrated cleanly with your system.

### DKMS Installation (Fallback)

If a pre-built package isn't available for your distro, Dynamic Kernel Module Support (DKMS) is the recommended fallback. It allows the module to be automatically rebuilt when you upgrade your kernel.

Because `dm-xor` is maintained as an out-of-tree external kernel module, DKMS requires you to have the kernel headers installed for your currently running kernel, along with standard build tools (`make`, `gcc`, etc.).

To install via DKMS:

```sh
sudo make dkms-install
```

This command will copy the source to `/usr/src/dm-xor-2.2.0/` and register, build, and install the module with DKMS. The module will load automatically via `modprobe dm-xor` or when requested by `dmsetup`.

To uninstall from DKMS:

```sh
sudo make dkms-uninstall
```

### Manual Build (Advanced)

If you need to build the module manually for testing or development purposes:

```sh
make
```

To insert the module into the running kernel:

```sh
sudo insmod dm-xor.ko
```
