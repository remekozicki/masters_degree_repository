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

# źródła implementacji AEAD
IMPL_SRCS := $(wildcard $(IMPL_DIR)/*.c)
IMPL_OBJS := $(IMPL_SRCS:.c=.o)

# wspólne narzędzia do testów
COMMON_SRCS := $(COMMON)/tests_common.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

# pliki z "main" od testów
KAT_SRC  := $(BASE)/tests/test_kat.c
FUNC_SRC := $(BASE)/tests/test_functional.c
KAT_OBJ  := $(KAT_SRC:.c=.o)
FUNC_OBJ := $(FUNC_SRC:.c=.o)

# binarki testów
KAT_BIN  := test-$(ALG)-kat
FUNC_BIN := test-$(ALG)-functional

# --- Random tests ---

RANDOM_SRC := $(BASE)/tests/test_random.c
RANDOM_OBJ := $(RANDOM_SRC:.c=.o)
RANDOM_BIN := test-$(ALG)-random

$(RANDOM_BIN): $(RANDOM_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

run-random: $(RANDOM_BIN)
	./$(RANDOM_BIN) "result-$(ALG)-random.csv"



.PHONY: all run-kat run-func clean

all: $(KAT_BIN) $(FUNC_BIN)

# ogólna reguła kompilacji .c -> .o
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# linkowanie testerów

$(KAT_BIN): $(KAT_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(FUNC_BIN): $(FUNC_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# uruchamianie

run-kat: $(KAT_BIN)
	./$(KAT_BIN) "$(KAT_FILE)"

# jak nie chcesz CSV, usuń argument "wyniki-...csv"
run-func: $(FUNC_BIN)
	./$(FUNC_BIN) "result-$(ALG)-functional.csv"

clean:
	rm -f $(KAT_BIN) $(FUNC_BIN) $(RANDOM_BIN)
	rm -f $(IMPL_OBJS) $(COMMON_OBJS) $(KAT_OBJ) $(FUNC_OBJ) $(RANDOM_OBJ)

