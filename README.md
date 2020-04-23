# testMonero
## Compilation on Ubuntu 18.04
Before of all, you must install Monero with this command (tested on Ubuntu 18.04):
```
sudo apt update

sudo apt install git build-essential cmake libboost-all-dev miniupnpc libunbound-dev graphviz doxygen libunwind8-dev pkg-config libssl-dev libcurl4-openssl-dev libgtest-dev libreadline-dev libzmq3-dev libsodium-dev libhidapi-dev libhidapi-libusb0

# go to home folder or where you want to clone Monero
cd ~
git clone --recursive -b release-v0.15 https://github.com/monero-project/monero.git

cd monero/

USE_SINGLE_BUILDDIR=1 make -j#core
```
##### Compile the testMonero

Once the Monero is compiles, the testMonero can be downloaded and compiled
as follows:

```
# make a build folder and enter it
mkdir build && cd build

# create the makefile
cmake -DMONERO_DIR=/path/to/monero_folder ..

# compile
make
```



