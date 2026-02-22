CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -D_POSIX_C_SOURCE=200809L
DEPFLAGS := -MMD -MP

# Algorithm: ascon | elephant | gift
ALG ?= ascon

BASE := .
COMMON := $(BASE)/common

ifeq ($(ALG),ascon)
  IMPL_DIR := $(BASE)/ascon/ref
  KAT_FILE := $(BASE)/ascon/LWC_AEAD_KAT_128_128.txt
endif
ifeq ($(ALG),elephant)
  IMPL_DIR := $(BASE)/elephant/ref
  KAT_FILE := $(BASE)/elephant/LWC_AEAD_KAT_128_96.txt
endif
ifeq ($(ALG),gift)
  IMPL_DIR := $(BASE)/gift-cofb/ref
  KAT_FILE := $(BASE)/gift-cofb/LWC_AEAD_KAT_128_128.txt
endif

ifeq ($(strip $(IMPL_DIR)),)
  $(error Unsupported ALG='$(ALG)'; expected one of: ascon elephant gift)
endif

INCLUDES := -I$(IMPL_DIR) -I$(COMMON)

ifeq ($(OS),Windows_NT)
  EXEEXT :=
  RUN_PREFIX :=
else
  EXEEXT :=
  RUN_PREFIX := ./
endif

# AEAD implementation sources
IMPL_SRCS := $(wildcard $(IMPL_DIR)/*.c)
IMPL_OBJS := $(IMPL_SRCS:.c=.o)

# Shared helpers and test mains with algorithm-specific object names.
COMMON_SRCS := $(COMMON)/tests_common.c
COMMON_OBJS := $(COMMON_SRCS:.c=.$(ALG).o)

KAT_SRC := $(BASE)/tests/test_kat.c
FUNC_SRC := $(BASE)/tests/test_functional.c
RANDOM_SRC := $(BASE)/tests/test_random.c
API_SRC := $(BASE)/tests/test_api.c

KAT_OBJ := $(KAT_SRC:.c=.$(ALG).o)
FUNC_OBJ := $(FUNC_SRC:.c=.$(ALG).o)
RANDOM_OBJ := $(RANDOM_SRC:.c=.$(ALG).o)
API_OBJ := $(API_SRC:.c=.$(ALG).o)

KAT_BIN := test-$(ALG)-kat$(EXEEXT)
FUNC_BIN := test-$(ALG)-functional$(EXEEXT)
RANDOM_BIN := test-$(ALG)-random$(EXEEXT)
API_BIN := test-$(ALG)-api$(EXEEXT)

DEPS := $(IMPL_OBJS:.o=.d) $(COMMON_OBJS:.o=.d) $(KAT_OBJ:.o=.d) $(FUNC_OBJ:.o=.d) $(RANDOM_OBJ:.o=.d) $(API_OBJ:.o=.d)

.PHONY: all run-kat run-func run-random run-api clean

all: $(KAT_BIN) $(FUNC_BIN)

# Generic compile rule for implementation files.
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c -o $@ $<

# Compile helper/test objects with per-algorithm suffix.
%.$(ALG).o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c -o $@ $<

$(KAT_BIN): $(KAT_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(FUNC_BIN): $(FUNC_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(RANDOM_BIN): $(RANDOM_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(API_BIN): $(API_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

run-kat: $(KAT_BIN)
	$(RUN_PREFIX)$(KAT_BIN) "$(KAT_FILE)"

run-func: $(FUNC_BIN)
	$(RUN_PREFIX)$(FUNC_BIN) "result-$(ALG)-functional.csv"

run-random: $(RANDOM_BIN)
	$(RUN_PREFIX)$(RANDOM_BIN) "result-$(ALG)-random.csv"

run-api: $(API_BIN)
	$(RUN_PREFIX)$(API_BIN) "result-$(ALG)-api.csv"

clean:
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue 'test-ascon-kat','test-ascon-functional','test-ascon-random','test-ascon-api','test-elephant-kat','test-elephant-functional','test-elephant-random','test-elephant-api','test-gift-kat','test-gift-functional','test-gift-random','test-gift-api'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './ascon/ref/*.o','./ascon/ref/*.d','./elephant/ref/*.o','./elephant/ref/*.d','./gift-cofb/ref/*.o','./gift-cofb/ref/*.d'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './tests/*.ascon.o','./tests/*.elephant.o','./tests/*.gift.o','./tests/*.d'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './common/*.ascon.o','./common/*.elephant.o','./common/*.gift.o','./common/*.d'; exit 0"
else
	-rm -f test-ascon-kat test-ascon-functional test-ascon-random test-ascon-api test-elephant-kat test-elephant-functional test-elephant-random test-elephant-api test-gift-kat test-gift-functional test-gift-random test-gift-api
	-rm -f $(BASE)/ascon/ref/*.o $(BASE)/ascon/ref/*.d $(BASE)/elephant/ref/*.o $(BASE)/elephant/ref/*.d $(BASE)/gift-cofb/ref/*.o $(BASE)/gift-cofb/ref/*.d
	-rm -f $(BASE)/tests/*.ascon.o $(BASE)/tests/*.elephant.o $(BASE)/tests/*.gift.o $(BASE)/tests/*.d
	-rm -f $(COMMON)/*.ascon.o $(COMMON)/*.elephant.o $(COMMON)/*.gift.o $(COMMON)/*.d
endif

-include $(DEPS)
