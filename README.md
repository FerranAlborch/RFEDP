# RFEDP - Randomized Functional Encryption for Differential Privacy
This repository contains the source code for the evaluation times for the randomized functional encryption schemes that appear in the thesis manuscript [Private Data Analysis over Encrypted Databases: Mixing Functional Encryption and Computational Differential Privacy](https://theses.hal.science/tel-04987654v1), prepared at the Doctoral School of the Institut Politechnique de Paris and Orange Innovation by Ferran Alborch Escobar. It includes code for evaluation times that were used in the paper [Computational Differential Privacy for Encrypted Databases Supporting Linear Queries](https://doi.org/10.56553/popets-2024-0131) published in the Proceedings on Privacy Enhancing Technologies (PoPETs), Issue 4, pages 583–604, 2024, and also in the paper [Simulation Secure Multi-input Quadratic Functional Encryption: Applications to Differential Privacy](https://eprint.iacr.org/2024/2050) as a preprint.    

**Note:** This code is a proof of concept implementation and not ready for produciton. As such, use in production at your own risk.

# Description

The purpose of this source code in C and C++ is to give estimates on the evaluation times of the three randomized functional encryption schemes proposed in the thesis. More specifically: the naive randomized inner-product functional encryption scheme based on function-hiding inner-product functional encryption (RIPFE FH) proposed in Section 4.2 of the thesis; the randomized inner-product functional encryption scheme based on standard inner-product functional encryption (RIPFE DDH) proposed in Section 4.3 of the thesis (and section 4 of the PoPETS article); and the randomized quadratic functional encryption scheme based on function-hiding inner-product functional encryption (RQFE FH) proposed in section 6.2 of the thesis (and section 5 of the preprint).

The implementations of the constructions based on function-hiding inner-product 


inner product functional encryption (RIPFE) scheme proposed in Section 4 of the article. It is a construction based on any generic inner product functional encryption (IPFE) scheme satisfying simulation security, and for this implementation we base ourselves on the scheme from Section 3 in the paper **Adaptive Simulation Security for Inner Product Functional Encryption** by Agrawal, Libert, Maitra and Titiu published at PKC 2020.

For more information on the choice of scheme and the implementation particulars as well as the results obtained we refer to Section 4.4.2 and Section 6.3.2 of the thesis. 

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
- [mcl](https://github.com/herumi/mcl/tree/master): Library for efficient computation over bilinear pairing groups. 

## Building Our Code

### Without Docker

1. Install required libraries.
```
sudo apt-get update
sudo apt-get install libgmp-dev
```

```
git clone https://github.com/herumi/mcl
cd mcl
make -j
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/lib
```

**Note** Temporary, if not add to .bashrc

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
