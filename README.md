# RIPFEDP - Randomized Inner Product Functional Encryption for Differential Privacy
This repository contains the source code for the evaluation times from the randomized inner product functional encryption scheme in the paper **Computational Differential Privacy for Encrypted Databases Supporting Linear Queries** accepted at Proceedings on Privacy Enhancing Technologies (PoPETs), Issue 4, 2024. 

**Note:** This code is a proof of concept implementation and not ready for produciton. As such, use in production at your own risk.

# Description

The purpose of this source code in C and C++ is to give estimates on the evaluation times of the randomized inner product functional encryption (RIPFE) scheme proposed in Section 4 of the article. It is a construction based on any generic inner product functional encryption (IPFE) scheme satisfying simulation security, and for this implementation we base ourselves on the scheme from Section 3 in the paper **Adaptive Simulation Security for Inner Product Functional Encryption** by Agrawal, Libert, Maitra and Titiu published at PKC 2020.

For more information on the choice of scheme and the implementation particulars as well as the results obtained we refer to Section 6 of the paper. For the exact schemes being implemented in this repository we refer to Appendix I of the paper.

# Directory Structure

- include/ Header files.
    - IPFE/ Header files concerning the implementation of the IPFE scheme.
    - RIPFE/ Header files concerning the implementation of the RIPFE scheme.
    - utils/ Header files concerning other useful functions.
    - config.h File containing the globally defined values.
- results/ Experimental results.
- src/ Source files.
    - IPFE/ Source files concerning the implementation of the IPFE scheme.
    - RIPFE/ Source files concerning the implementation of the RIPFE scheme.
    - utils/ Source files concerning other useful functions.
- Dockerfile Dockerfile.
- LICENSE Apache 2.0 License.
- Makefile Makefile.
- README This file.
- test.c Source code for running the full RIPFE scheme.
- script.sh Shell script to run the tests with the same parameters as in the paper.

# Building and Running Our Code

## Requirements 

- [GMP](https://gmplib.org/): Library to handle multiple precision integers, under the GNU LGPL v3 license. The version used is 6.2.1. 

## Building Our Code

### Without Docker

1. Install required libraries.
```
sudo apt-get update
sudo apt-get install libgmp-dev
```
2. Run makefile.
```
make release
```

### With Docker

1. Install Docker.
```
sudo apt-get install docker.io
sudo snap install docker
```

2. Build Docker image.
```
docker build -t ripfedp .
```

## Running our code

### Without Docker

To run the code for a test for the full RIPFE scheme use the following command
```
./RFEDP l Q |X| |Y|
```
where $\ell,Q,|X|,|Y|$ are positive integers representing the several parameters of the scheme. For a thorough explanation we refer to Section 6.2 of the paper. We also recommend looking into the ```include/config.h``` file to see the global parameters of the scheme.

**Note:** As commented in Section 6.2 of the paper it is important that for whatever set of parameters is used, the inequality

$$\ell\cdot 2^{|X|}\cdot 2^{|Y|}+1000\cdot Q\cdot 2^{|Y|}\leq 2^{40}$$

is satisfied so that the discrete logarithm performed during decryption takes a reasonable ammount of time.

### With Docker

First run the docker image.
```
docker run -it ripfedp
```

This command will give you access to the command line inside the image. Then you can run a test using the same command as without Docker.

## Obtaining Results

To perform the analysis that gave the results published in the paper run the command
```
./script.sh
```
which will test for the specific parameters of the paper different $\ell$, from 10 to 1 000 000. The results will be output to ```results/OutputK.txt``` for each $\ell=10^K$.

**Note:** We used a laptop with Ubuntu 22.04, Intel i7-1365U (3.9 GHz) and 32 GB of RAM to run our code. It required about 2GB of memory and about 4 hours and 30 minutes.
