# LittleExtFS

**Acknowledgment and Disclaimer:** This is a slightly modified version of [LittleFS-RK](https://github.com/rickkas7/LittleFS-RK) library, adapted to run on Gen 3 Particle devices (tested on a Boron). It's a worse derived version from the original in a sense, since the posix functions (open, read, write, close,...) will **not** work on this version and are instead replaced with equivalents prefixed with *lefs_*. Don't blame me, the posix functions are implemented in the deviceOS, so there's not much I can do to fix that (or maybe there is, and someone will improve that).

Port of LittleFS for Particle Gen 3 devices (external memory chip, as opposed to Particle's own implementation of LittleFS on the 2MB internal memory).

**Warning:** This only works on Gen 3 devices (Argon, Boron, B Series...), although I actually **only** tested it on the Boron! For Gen 2 devices, please use Rick's version instead.

**Warning:** As this point in time, it's just a proof-of-concept for testing. There are almost certainly still bugs that haven't been found yet as it has not been extensively tested yet!

- This is based on the Particle LittleFS implementation in Device OS: [https://github.com/particle-iot/device-os/tree/develop/third_party/littlefs](https://github.com/particle-iot/device-os/tree/develop/third_party/littlefs).

- It contains the POSIX wrappers from Device OS: [https://github.com/particle-iot/device-os/tree/develop/hal/src/nRF52840/littlefs](https://github.com/particle-iot/device-os/tree/develop/hal/src/nRF52840/littlefs).

- It contains other hacked bits of Device OS needed to make it compile and link from user firmware.

- The POSIX file system API calls are the same as [are documented for the Boron](https://docs.particle.io/reference/device-os/firmware/boron/#file-system).

- Tested with Winbond, ISSI, and Macronix SPI NOR flash chips.  

- It even works with the MX25L25645G 256 Mbit (32 Mbyte) flash chip, which I could not get to work reliably with SPIFFS. See note in LargeFileTest.cpp; you must enable 32-bit addressing in SpiFlashRK using `spiFlash.set4ByteAddressing(true);` for this to work properly.

## Usage

You'll probably need some includes:

```cpp
#include "LittleExtFS.h"

#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace nsLittleExtFS;
```

This code uses the [SpiFlashRK library](https://github.com/rickkas7/SpiFlashRK) to interface to the flash chip. You typically use one of these lines depending on the brand, SPI port, and CS line:

```cpp
// Pick a chip, port, and CS line
// SpiFlashISSI spiFlash(SPI, A5);
// SpiFlashWinbond spiFlash(SPI, A5);
// SpiFlashMacronix spiFlash(SPI, A5);
// SpiFlashWinbond spiFlash(SPI, A5);
// SpiFlashMacronix spiFlash(SPI, A5);
```

You then allocate a `LittleExtFS` object as a global:

```
LittleExtFS fs(&spiFlash, 0, 256);
```

The parameters are:

- `&spiFlash` the object for your flash chip
- `0` the start sector for the file system (0 = beginning of chip)
- `256` replace with the number of 4096-byte sectors to use for the file system. 256 * 4096 = 1,048,576 bytes = 1 Mbyte, the size of an 8 Mbit SPI flash chip. 

Note: You must only ever allocate one LittleExtFS object. Bad things will happen if you create more than one. You can allocate it with `new` but don't allocate it on the stack.

Finally, in `setup()`, initialize the SPI flash and mount the file system. This will format it if it has not been formatted.

```cpp
spiFlash.begin();
int res = fs.mount();
Log.info("fs.mount() = %d", res);
```

## Testing

There is no functional test program yet, I'm still updating the example from the original library:

- FileSystemTest: A simple app
- LargeFileTest: A test that writes larger files to test performance


## Version History

### 0.0.1 (2023-03-27)

- Initial testing version. It probably still has bugs!

