# SNOW

SNOW stands for Wireless \*\*\* Network Sniffer, with an imaginative, reversed. and open mind.
Instead of being a clutchy piece of security software as most sniffers are, snow has only three missions, which it fulfils well:

* Capture as many single packets your network card can do
* Filter-out as many uninteresting packets as possible (quickly)
* Retransmit _minimal_ information about the packet on a [zeromq](http://www.zeromq.org/) endpoint to _hermes_

## Compile

NOTE: Enable verbose debug output at compile time using the `-DDEBUG` flag for gcc.

### As an OpenWRT package:

```bash
rm dl/snow-0.2.1.tar.bz2
make package/snow/install V=99
scp bin/ramips/packages/snow_0.2.1-1_ramips.ipk root@[remoterouter]:.
```

### On the local machine:

Snow needs elevated privileges in order to reconfigure your wireless network card.

```bash
./autogen.sh
./configure --libczmq=<czmq_dir> --libuci=<libuci_dir>
make
sudo make install
sudo mkdir -p /etc/config
sudo cp files/snow /etc/config/snow
sudo snow 
```

## Test

You can run the tests using either the `make check` target or the `./snow\_selftest` executable.


## Getting Started on OpenWRT

* Install the package.
* The app automatically imports its configuration from `/etc/config/snow` UCI file.
* You can override some parameters; run  `snow -h` to check that out.

## Examples

Run snow on another WLAN interface:

```bash
snow -i wlan1
```

Run snow for up to 100 reads:

```bash
snow -n 100
```

Run snow onto a different zeromq endpoint:

```bash
snow -e tcp://iso3103.net:1338
```

## UCI options

* snow.capture.iface
WLAN interface to use as capture interface.
Default value: "wlan0"

* snow.capture.ignoreap
Boolean value that decides whether we recognize and filter-out all AP-originating messages or not.
Default value: 1

* snow.capture.ignoredata
Boolean value that decides whether we skip all data packets or not.
Default value: 1

* snow.capture.timeout
Time before libpcap decides of a timeout and exits.
Default value: 1000 (ms)

* snow.capture.capsize
Maximum size inside of a packet that is read by libpcap.
Default value: 256

* snow.transmit.endpoint
Endpoint where the data is published.
Default value: tcp://localhost:10070

* snow.transmit.hwm
High-water mark to use on PUSH socket.
Default value: 100

* snow.transmit.linger
Linger to use on PUSH socket.
Default value: 0

* snow.debug.maxruns
Debug usage, enable to run snow for up to <maxruns> bare packets.
Default value: -1 (infinite)

Changelog
---------

### 0.3.0

**Date**: 30th August 2013

* Add wait_ntp parameter to wait for clock sync
*Adaptations for standalone mode
* Use far more robust FNV1 hash for mac addresses
* Improve output char encoding
* Fix init script and mon0 interface creation

### 0.2.2

**Date**: 10th April 2013

* Use iw script to sniff even on an active chip
* Uses and reports SSIDs
* Bugfixes

License
-------

MIT
