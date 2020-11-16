CFLAGS := -Wall -O2 -Werror -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing 
SHELL := /usr/bin/bash

# each binary command is built from a single .c file
BIN := src/createmany			\
	src/dumb_setxattr		\
	src/handle_cat			\
	src/bulk_create_paths		\
	src/find_xattrs

DEPS := $(wildcard src/*.d)

all: $(BIN)

ifneq ($(DEPS),)
-include $(DEPS)
endif

$(BIN): %: %.c Makefile
	gcc $(CFLAGS) -MD -MP -MF $*.d $< -o $@

.PHONY: clean
clean:
	@rm -f $(BIN) $(DEPS)

#
# Make sure we only have all three items needed for each test: entry in
# sequence, test script in tests/, and output in golden/.
#
.PHONY: check-test-files
check-test-files:
	@for t in $$(grep -v "^#" sequence); do			\
		test -e "tests/$$t" ||				\
			echo "no test for list entry: $$t";	\
		t=$${t%%.sh};					\
		test -e "golden/$$t" ||				\
			echo "no output for list entry: $$t";	\
	done;							\
	for t in golden/*; do					\
		t=$$(basename "$$t");				\
		grep -q "^$$t.sh$$" sequence ||			\
			echo "output not in list: $$t";		\
	done;							\
	for t in tests/*; do					\
		t=$$(basename "$$t");				\
		test "$$t" == "list" && continue;		\
		grep -q "^$$t$$" sequence ||			\
			echo "test not in list: $$t";		\
	done
