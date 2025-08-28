#
# Software Name : RIPFEDP
# Version: 1.1
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at 
#     http://www.apache.org/licenses/LICENSE-2.0 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Ferran Alborch Escobar <ferran.alborch@gmail.com>
#

# Use the latest Ubuntu image
FROM ubuntu:latest

# Set environment variables to avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get update && \
    apt-get install -y \
    build-essential wget \
    libgmp-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* 

# Create a directory for the library source code
WORKDIR /usr/src/mycpp-lib

# Copy the library source code and Makefile into the container
COPY . .

RUN wget https://github.com/herumi/mcl/archive/refs/tags/v3.03.tar.gz \
    && tar -xzvf v3.03.tar.gz \
    && mv mcl-3.03 mcl \
    && cd mcl \
    && make -j$(nproc) \
    && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/lib \
    && cd .. 


# Compile the library using the Makefile
RUN make release -j$(nproc)

ENTRYPOINT LD_LIBRARY_PATH=$PWD/mcl/lib /bin/bash
