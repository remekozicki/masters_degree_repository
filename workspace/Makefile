CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith -D_POSIX_C_SOURCE=200809L
DEPFLAGS := -MMD -MP

# Algorithm: ascon | elephant | gift
ALG ?= ascon

BASE := .
COMMON := $(BASE)/common
TESTS := $(BASE)/tests
FUNC_TESTS := $(TESTS)/functional_tests
PERF_TESTS := $(TESTS)/throughput_and_latency
MICRO_TESTS := $(TESTS)/micro_internal

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

KAT_SRC := $(FUNC_TESTS)/test_kat.c
FUNC_SRC := $(FUNC_TESTS)/test_functional.c
RANDOM_SRC := $(FUNC_TESTS)/test_random.c
API_SRC := $(FUNC_TESTS)/test_api.c
THROUGHPUT_SRC := $(PERF_TESTS)/test_throughput.c
LATENCY_SRC := $(PERF_TESTS)/test_latency.c
MICRO_INTERNAL_SRC := $(MICRO_TESTS)/test_micro_internal.c

KAT_OBJ := $(KAT_SRC:.c=.$(ALG).o)
FUNC_OBJ := $(FUNC_SRC:.c=.$(ALG).o)
RANDOM_OBJ := $(RANDOM_SRC:.c=.$(ALG).o)
API_OBJ := $(API_SRC:.c=.$(ALG).o)
THROUGHPUT_OBJ := $(THROUGHPUT_SRC:.c=.$(ALG).o)
LATENCY_OBJ := $(LATENCY_SRC:.c=.$(ALG).o)
MICRO_INTERNAL_OBJ := $(MICRO_INTERNAL_SRC:.c=.$(ALG).o)

KAT_BIN := test-$(ALG)-kat$(EXEEXT)
FUNC_BIN := test-$(ALG)-functional$(EXEEXT)
RANDOM_BIN := test-$(ALG)-random$(EXEEXT)
API_BIN := test-$(ALG)-api$(EXEEXT)
THROUGHPUT_BIN := test-$(ALG)-throughput$(EXEEXT)
LATENCY_BIN := test-$(ALG)-latency$(EXEEXT)
MICRO_INTERNAL_BIN := test-$(ALG)-micro-internal$(EXEEXT)

DEPS := $(IMPL_OBJS:.o=.d) $(COMMON_OBJS:.o=.d) $(KAT_OBJ:.o=.d) $(FUNC_OBJ:.o=.d) $(RANDOM_OBJ:.o=.d) $(API_OBJ:.o=.d) $(THROUGHPUT_OBJ:.o=.d) $(LATENCY_OBJ:.o=.d) $(MICRO_INTERNAL_OBJ:.o=.d)

.PHONY: all run-kat run-func run-random run-api run-throughput run-latency run-micro-internal run-perf clean

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

$(THROUGHPUT_BIN): $(THROUGHPUT_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(LATENCY_BIN): $(LATENCY_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(MICRO_INTERNAL_BIN): $(MICRO_INTERNAL_OBJ) $(COMMON_OBJS) $(IMPL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

run-kat: $(KAT_BIN)
	$(RUN_PREFIX)$(KAT_BIN) "$(KAT_FILE)"

run-func: $(FUNC_BIN)
	$(RUN_PREFIX)$(FUNC_BIN) "result-$(ALG)-functional.csv"

run-random: $(RANDOM_BIN)
	$(RUN_PREFIX)$(RANDOM_BIN) "result-$(ALG)-random.csv"

run-api: $(API_BIN)
	$(RUN_PREFIX)$(API_BIN) "result-$(ALG)-api.csv"

run-throughput: $(THROUGHPUT_BIN)
	$(RUN_PREFIX)$(THROUGHPUT_BIN) "result-$(ALG)-throughput.csv"

run-latency: $(LATENCY_BIN)
	$(RUN_PREFIX)$(LATENCY_BIN) "result-$(ALG)-latency.csv"

run-micro-internal: $(MICRO_INTERNAL_BIN)
	$(RUN_PREFIX)$(MICRO_INTERNAL_BIN) "result-$(ALG)-micro-internal.csv"

run-perf: run-throughput run-latency run-micro-internal

clean:
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue 'test-ascon-kat','test-ascon-functional','test-ascon-random','test-ascon-api','test-ascon-throughput','test-ascon-latency','test-ascon-micro-internal','test-elephant-kat','test-elephant-functional','test-elephant-random','test-elephant-api','test-elephant-throughput','test-elephant-latency','test-elephant-micro-internal','test-gift-kat','test-gift-functional','test-gift-random','test-gift-api','test-gift-throughput','test-gift-latency','test-gift-micro-internal'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './ascon/ref/*.o','./ascon/ref/*.d','./elephant/ref/*.o','./elephant/ref/*.d','./gift-cofb/ref/*.o','./gift-cofb/ref/*.d'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './tests/*.ascon.o','./tests/*.elephant.o','./tests/*.gift.o','./tests/*.d','./tests/functional_tests/*.ascon.o','./tests/functional_tests/*.elephant.o','./tests/functional_tests/*.gift.o','./tests/functional_tests/*.d','./tests/throughput_and_latency/*.ascon.o','./tests/throughput_and_latency/*.elephant.o','./tests/throughput_and_latency/*.gift.o','./tests/throughput_and_latency/*.d','./tests/micro_internal/*.ascon.o','./tests/micro_internal/*.elephant.o','./tests/micro_internal/*.gift.o','./tests/micro_internal/*.d'; exit 0"
	-powershell -NoProfile -Command "Remove-Item -Force -ErrorAction SilentlyContinue './common/*.ascon.o','./common/*.elephant.o','./common/*.gift.o','./common/*.d'; exit 0"
else
	-rm -f test-ascon-kat test-ascon-functional test-ascon-random test-ascon-api test-ascon-throughput test-ascon-latency test-ascon-micro-internal test-elephant-kat test-elephant-functional test-elephant-random test-elephant-api test-elephant-throughput test-elephant-latency test-elephant-micro-internal test-gift-kat test-gift-functional test-gift-random test-gift-api test-gift-throughput test-gift-latency test-gift-micro-internal
	-rm -f $(BASE)/ascon/ref/*.o $(BASE)/ascon/ref/*.d $(BASE)/elephant/ref/*.o $(BASE)/elephant/ref/*.d $(BASE)/gift-cofb/ref/*.o $(BASE)/gift-cofb/ref/*.d
	-rm -f $(BASE)/tests/*.ascon.o $(BASE)/tests/*.elephant.o $(BASE)/tests/*.gift.o $(BASE)/tests/*.d $(BASE)/tests/functional_tests/*.ascon.o $(BASE)/tests/functional_tests/*.elephant.o $(BASE)/tests/functional_tests/*.gift.o $(BASE)/tests/functional_tests/*.d $(BASE)/tests/throughput_and_latency/*.ascon.o $(BASE)/tests/throughput_and_latency/*.elephant.o $(BASE)/tests/throughput_and_latency/*.gift.o $(BASE)/tests/throughput_and_latency/*.d $(BASE)/tests/micro_internal/*.ascon.o $(BASE)/tests/micro_internal/*.elephant.o $(BASE)/tests/micro_internal/*.gift.o $(BASE)/tests/micro_internal/*.d
	-rm -f $(COMMON)/*.ascon.o $(COMMON)/*.elephant.o $(COMMON)/*.gift.o $(COMMON)/*.d
endif

-include $(DEPS)
