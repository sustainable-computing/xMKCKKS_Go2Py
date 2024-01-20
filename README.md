# xMKCKKS_Go2Py
Python implementation for xMKCKKS, based on the Golang Multi-key CKKS Homomorphic Encryption library.

## Introduction

This Python library implements the xMKCKKS scheme proposed in "Privacy-preserving Federated Learning based on Multi-key Homomorphic Encryption" (https://arxiv.org/abs/2104.06824).

It is built on top of the MKCKKS_Go2Py (https://github.com/sustainable-computing/MKCKKS_Go2Py) library for Multi-key Homomorphic Encryption (MK-HE) in Federated Learning (FL). 

The Golang code base for MKCKKS is MKHE-KKLSS (https://github.com/SNUCP/MKHE-KKLSS), which is from the paper "Asymptotically Faster Multi-Key Homomorphic Encryption from Homomorphic Gadget Decomposition" (https://eprint.iacr.org/2022/347), published in ACM CCS'23.

This library will build a C-style dynamic link library (dll) from the Golang code using cgo, allowing calling go functions from Python programs using ctypes.

We implement this library to perform MK-HE in the context of Federated Learning (FL), currently this library supports:
- Public & private key generation
- Public key aggregation (for xMKCKKS)
- Encoding & encryption on a list of double data using public key
- Homomorphic addition between 2 ciphertexts
- Homomorphic multiplication between a ciphertext and a constant value
- Partial decryption
- Aggregating the partial decryption results and decoding

Note: Our implementation considers encrypting double data type, you will need to make your own changes to encrypt compelx data type.

## Prerequisites
- Go and cgo
- Python and ctypes


## How to Use

The C-style dll needs to be generated for different platforms, to generate your own dll, open a terminal at the root directory of this project and enter:

`go build -o xmkckks.so -buildmode=c-shared export.go`

This generates a dll named xmkckks.so from the export.go file. Please refer to the jupyter notebook tutorials.ipynb for details of how to import this dll in Python and perform HE operations. 



## Instructions for the Golang Code Base:
Source: [MKHE-KKLSS](https://github.com/SNUCP/MKHE-KKLSS)

This repository provides an implementation of the Multi-key Homomorphic Encryption scheme in (https://eprint.iacr.org/2022/347).
This project was supported by Samsung Research, Samsung Electronics Co., Ltd.


### LICENSE

Attribution-NonCommercial 2.0 Generic (CC BY-NC 2.0)

### HOW TO INSTALL

use "go mod vendor" 

### HOW TO RUN UNITTEST

1. go to target folder (e.g for mkckks "cd mkckks")
2. run go test command "go test -args -n=x" (x is the number of parties e.g for 2 parites set x to 2)

### HOW TO RUN BENCHMARK
1. go to target folder (e.g for mkckks "cd mkckks")
2. run go benchmark command "go test -bench=. -benchtime=10x -timeout=0 -args -n=4" (This runs 10 repetition of benchmark for the 4 party case)