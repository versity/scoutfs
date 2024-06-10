CFLAGS := -Wall -O2 -Werror -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing -I ../kmod/src
SHELL := /usr/bin/bash

# each binary command is built from a single .c file
BIN := src/createmany			\
	src/dumb_renameat2		\
	src/dumb_setxattr		\
	src/handle_cat			\
	src/handle_fsetxattr		\
	src/bulk_create_paths		\
	src/stage_tmpfile		\
	src/find_xattrs			\
	src/create_xattr_loop		\
	src/fragmented_data_extents	\
	src/o_tmpfile_umask		\
	src/o_tmpfile_linkat		\
	src/mmap_stress			\
	src/mmap_validate

DEPS := $(wildcard src/*.d)

all: $(BIN)

ifneq ($(DEPS),)
-include $(DEPS)
endif

src/mmap_stress: LIBS+=-lpthread

$(BIN): %: %.c Makefile
	gcc $(CFLAGS) -MD -MP -MF $*.d $< -o $@ $(LIBS)

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
