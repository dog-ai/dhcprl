# 👀 Monitor DHCP requests on a LAN 💻

[![Build Status](https://travis-ci.org/dog-ai/dhcprl.svg?branch=master)](https://travis-ci.org/dog-ai/dhcprl)
[![Coverage Status](https://coveralls.io/repos/github/dog-ai/dhcprl/badge.svg?branch=master)](https://coveralls.io/github/dog-ai/dhcprl?branch=master)
[![](https://img.shields.io/github/release/dog-ai/dhcprl.svg)](https://github.com/dog-ai/dhcprl/releases)
[![](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) 

Monitor DHCP requests on a LAN.

### How to use

#### Use it in your terminal
Run the daemon listening on interface `eth0` and socket `/var/run/dhcprl.sock`
```
dhcprld -i eth0 -s /var/run/dhcprl.sock
```

### How to build
Create build directory
```
mkdir build
```

Change current directory
```
cd build
```

Generate Makefile
```
cmake ..
```

Compile source
```
make
```
