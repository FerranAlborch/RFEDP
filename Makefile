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
CPPFLAGS = -std=c++20 -Wall -O2 -Wextra

# Project and executable
PROJECT = RFEDP
BIN = $(PROJECT)

# Source directory
SOURCE = $(shell find src -type f | grep '\.c$$')
CPPSOURCE = $(shell find src -type f | grep '\.cpp$$')

# Test files
TEST_SOURCES = test_ripfe_DDH.c test_ripfe_FH.c test_rqfe_FH.c

# Object files
OBJECT = $(SOURCE:.c=.o) $(CPPSOURCE:.cpp=.o)

# Include directory
INCLUDE_DIR = include
MCL_INCLUDE_DIR = $(MCL_INCLUDE_PATH)

# External libraries
EXT_LIB = -lgmp -lm -lmclbn384_256 -lmcl
MCL_LIB_PATH = $(MCL_LIB_PATH)

# Build all target
all: $(BIN) $(TEST_SOURCES:.c=.out)

# Link executable
$(BIN): $(OBJECT)
	$(CPP) $(CPPFLAGS) $^ -o $@ -I$(INCLUDE_DIR) -I$(MCL_INCLUDE_DIR) -L$(MCL_LIB_PATH) $(EXT_LIB) 

# Compile object files
%.o: %.c
	$(CPP) $(CPPFLAGS) -I$(INCLUDE_DIR) -I$(MCL_INCLUDE_DIR) -c $< -o $@

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -I$(INCLUDE_DIR) -I$(MCL_INCLUDE_DIR) -c $< -o $@

# Build test executables
%.out: %.c
	$(CPP) $(CPPFLAGS) $< -o $@ -I$(INCLUDE_DIR) -I$(MCL_INCLUDE_DIR) -L$(MCL_LIB_PATH) $(EXT_LIB)

# Clean target
clean:
	rm -f $(OBJECT) $(BIN) $(TEST_SOURCES:.c=.out)

# Debug flag
debug: CFLAGS += -g
debug: CPPFLAGS += -g
debug: all

# Release flag
release: CFLAGS += -O3 -march=native -mtune=native 
release: CPPFLAGS += -O3 -march=native -mtune=native 
release: all