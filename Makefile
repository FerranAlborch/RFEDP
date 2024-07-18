#
# Software Name : RFEDP
# Version: 1.0
# SPDX-FileCopyrightText: Copyright (c) 2024[-2024] Orange Innovation
#
# This software is confidential and proprietary information of Orange Innovation.
# You shall not disclose such Confidential Information and shall not copy, use or distribute it
# in whole or in part without the prior written consent of Orange Innovation
#
# Author: Ferran Alborch Escobar
#

# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -Wextra
CPP = g++
CPPFLAGS = -std=c++20  -Wall -O2 -Wextra

# Project and executable
PROJECT = RFEDP
BIN = $(PROJECT)

# Source directory
SOURCE = $(shell find src -type f | grep '\.c$$')
#SOURCE += test_ripfe_DDH.c
#SOURCE += test_ripfe_FH.c
SOURCE += test_rqfe_FH.c
CPPSOURCE = $(shell find src -type f | grep '\.cpp$$')

# Object files 
OBJECT = $(SOURCE:.c=.o) $(CPPSOURCE:.cpp=.o)
# $(info $$OBJECT is [${OBJECT}])

# Include directory
INCLUDE_DIR = include

# External libraries
EXT_LIB = -lgmp -lm -lmclbn384_256 -lmcl
# EXT_LIB += -fopenmp

# Build all target
all: $(BIN)

# Link executable
$(BIN): $(OBJECT)
	$(CPP) $(CPPFLAGS) $^ -o $@ -I$(INCLUDE_DIR) $(EXT_LIB)

%.o: %.c
	$(CPP) $(CPPFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Compile object files
%.o: %.cpp
	$(CPP) $(CPPFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

#Clean target
clean:
	rm -f $(OBJECT) $(BIN)

# Debug flag
debug: CFLAGS += -g
debug: CPPFLAGS += -g
debug: all

# Release flag
release: CFLAGS += -O3 -march=native -mtune=native 
release: CPPFLAGS += -O3 -march=native -mtune=native 
release: all


