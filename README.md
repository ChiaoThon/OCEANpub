# OCEANpub

## Introduction
This repo contains the prototype code for OCEAN (the paper is coming later), our extension of [FIT](https://ieeexplore.ieee.org/document/10646638), which aims to further reduce the (overall) communication cost and to make best use of the wasted slots in each channel-packed ciphertext.

## Required Packages
 - g++ (version >= 8)
 - cmake
 - make
 - libgmp-dev
 - libssl-dev  
 - SEAL 3.3.2
 - Eigen 3.3

## Main Files

The `test_conv.cpp` in `tests/` folder is the convolution from CrypTFlow2.

The `test_relu.cpp` in `tests/` folder is the ReLU from CrypTFlow2.

The `test_reconv.cpp` in `tests/` folder is relu-convolution, with optimization, proposed in FIT.

The `test_oceanpub.cpp` in `tests/` folder is relu-convolution of our proposed OCEAN.

The `netconfig.sh` in main folder is the traffic control module that one can follow to configure the bandwidth and round trip time for running the protocol in single machine.

## Compilation

To compile the repo:

```
mkdir build && cd build
cmake ..
make [-j] //optionally use -j for faster compilation
```

## Running Tests

In `build/bin/` folder, run the tests as follows:

In one terminal: `./<test> r=1`, and in another terminal: `./<test> r=2`

## Issues

This repo is under construction and any feedback is highly welcomed and appreciated.

## Credits

This repo is developed based on [CrypTFlow2](https://github.com/mpc-msri/EzPC/tree/master/SCI) and the `netconfig.sh`, with added instructions, is taken from [Cheetah](https://github.com/Alibaba-Gemini-Lab/OpenCheetah/tree/main/scripts).
