
#CC = gcc
CC = clang
CFLAGS = -Wall -O3 -mtune=native
NFL_AVX = -DNFL_OPTIMIZED=ON -DNTT_AVX2

# Detect architecture for conditional flags
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    # x86_64: enable AES-NI and AVX2 intrinsics
    AES_FLAGS = -maes
    AVX_FLAGS = -mavx2
else ifeq ($(UNAME_M),i386)
    # i386: enable AES-NI intrinsics (no AVX2 on 32-bit)
    AES_FLAGS = -maes
    AVX_FLAGS =
else ifeq ($(UNAME_M),i686)
    # i686: enable AES-NI intrinsics (no AVX2 on 32-bit)
    AES_FLAGS = -maes
    AVX_FLAGS =
else
    # ARM64 (arm64/aarch64) or other architectures: don't use x86-specific flags
    # macOS ARM64 uses "arm64", Linux ARM64 uses "aarch64"
    AES_FLAGS =
    AVX_FLAGS =
endif

CVECFLAGS := $(CFLAGS) $(AVX_FLAGS) -ftree-vectorize #-fopt-info-vec-optimized
CFLAGS += -fno-tree-vectorize

EXEC = signature_tests sampling_tests timing main_signature

OBJ = arithmetic.o random.o crt_trees.o

HDR = common.h

all: sampling_tests signature_tests

timing: timing.o crt_trees.o ibe.o signature.o sampling.o random.o arithmetic.o cpucycles.o
	$(CC) $(CFLAGS) -o $@ $^ -lm

signature_tests: signature_tests.o ibe.o signature.o sampling.o random.o arithmetic.o crt_trees.o
	$(CC) $(CFLAGS) -o $@ $^ -lm

main_signature: main_signature.o ibe.o signature.o sampling.o random.o $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lm

sampling_tests: sampling_tests.o sampling.o random.o arithmetic.o crt_trees.o
	$(CC) $(CFLAGS) -o $@ $^ -lm


arithmetic.o: arithmetic.c random.o $(HDR)
	$(CC) $(CVECFLAGS) -c -o $@ $<

sampling.o: sampling.c random.o $(HDR)
	$(CC) $(CVECFLAGS) -c -o $@ $<

random.o: random.c
	$(CC) $(CVECFLAGS) $(AES_FLAGS) -c -o $@ $<

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(EXEC) *.o *.s
