# ClawTower Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2

PRELOAD_DIR = src/preload

.PHONY: all clean libclawguard libclawguard-v2 test-interpose cargo-test

all: libclawguard libclawguard-v2 test-interpose

# Original v1 library
libclawguard: $(PRELOAD_DIR)/interpose.c
	$(CC) -shared -fPIC $(CFLAGS) -o libclawguard_v1.so $< -ldl

# New v2 behavioral engine
libclawguard-v2: $(PRELOAD_DIR)/interpose_v2.c
	$(CC) -shared -fPIC $(CFLAGS) -o libclawguard.so $< -ldl -lpthread -lm

# Test program
test-interpose: $(PRELOAD_DIR)/test_interpose.c
	$(CC) $(CFLAGS) -o test_interpose $< -ldl

# Run tests
test: libclawguard-v2 test-interpose
	LD_PRELOAD=./libclawguard.so ./test_interpose

# Run Rust tests
cargo-test:
	export PATH="$$HOME/.cargo/bin:$$PATH" && cargo test

clean:
	rm -f libclawguard.so libclawguard_v1.so test_interpose
