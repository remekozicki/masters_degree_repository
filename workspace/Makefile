CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -D_POSIX_C_SOURCE=200809L

# wybór algorytmu: ascon | elephant | gift
ALG ?= ascon

# bazowe ścieżki liczone od katalogu z Makefile (czyli ./workspace)
BASE := .
COMMON := $(BASE)/common

ifeq ($(ALG),ascon)
  IMPL_DIR := $(BASE)/ascon/ref
  KAT_FILE := $(BASE)/ascon/LWC_AEAD_KAT_128_128.txt
endif
ifeq ($(ALG),elephant)
  IMPL_DIR := $(BASE)/elephant/ref
  KAT_FILE := $(BASE)/elephant/LWC_AEAD_KAT_128_128.txt
endif
ifeq ($(ALG),gift)
  IMPL_DIR := $(BASE)/gift-cofb/ref
  KAT_FILE := $(BASE)/gift-cofb/LWC_AEAD_KAT_128_128.txt
endif

INCLUDES := -I$(IMPL_DIR) -I$(COMMON)
SRCS := $(COMMON)/bench.c $(wildcard $(IMPL_DIR)/*.c)
BIN := bench-$(ALG)

.PHONY: all run-kat run-func clean

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS)

run-kat: $(BIN)
	./$(BIN) --kat "$(KAT_FILE)"

run-func: $(BIN)
	./$(BIN) --functional

clean:
	rm -f bench-*
