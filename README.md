# 👀 Monitor DHCP requests on a LAN 💻

# Build

1. `mkdir build`
2. `cd build`
3. `cmake ..`
4. `make`

# Build for Raspberry Pi (cross-compile)
Note: Requires the ARM cross compiler toolchain installed and configured in your environment.

1. `mkdir build`
2. `cd build`
3. `cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/platforms/linux/toolchain/arm-linux-gnueabihf.cmake ..`
4. `make`