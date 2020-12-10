#
# The userspace utils and kernel module share definitions of physical
# structures and ioctls.  If we're in the repo we include the kmod
# headers directly, and hash them directly to calculate the format hash.
#
# If we're creating a standalone tarball for distribution we copy the
# headers out of the kmod dir into the tarball.  And then when we're
# building in that tarball we use the headers in src/ directly.
#
FMTIOC_H := format.h ioctl.h
FMTIOC_DIST := $(addprefix src/,$(FMTIOC_H))
FMTIOC_KMOD := $(addprefix ../kmod/src/,$(FMTIOC_H))

ifneq ($(wildcard $(firstword $(FMTIOC_KMOD))),)
HASH_FILES := $(FMTIOC_KMOD)
else
HASH_FILES := $(FMTIOC_DIST)
endif
SCOUTFS_FORMAT_HASH := $(shell cat $(HASH_FILES) | md5sum | cut -b1-16)

CFLAGS := -Wall -O2 -Werror -D_FILE_OFFSET_BITS=64 -g -msse4.2 \
	-fno-strict-aliasing \
	-DSCOUTFS_FORMAT_HASH=0x$(SCOUTFS_FORMAT_HASH)LLU

ifneq ($(wildcard $(firstword $(FMTIOC_KMOD))),)
CFLAGS += -I../kmod/src
endif

BIN := src/scoutfs
OBJ := $(patsubst %.c,%.o,$(wildcard src/*.c))
DEPS := $(wildcard */*.d)

all: $(BIN)

ifneq ($(DEPS),)
-include $(DEPS)
endif

ifeq ($(V), )
QU = @echo
VE = @
else
QU = @:
VE = 
endif

$(BIN): $(OBJ)
	$(QU)  [BIN $@]
	$(VE)gcc -o $@ $^ -luuid -lm -lcrypto -lblkid

%.o %.d: %.c Makefile sparse.sh
	$(QU)  [CC $<]
	$(VE)gcc $(CFLAGS) -MD -MP -MF $*.d -c $< -o $*.o
	$(QU)  [SP $<]
	$(VE)./sparse.sh -Wbitwise -D__CHECKER__ $(CFLAGS) $<

.PHONY: .FORCE

# - We use the git describe from tags to set up the RPM versioning
RPM_VERSION := $(shell git describe --long --tags | awk -F '-' '{gsub(/^v/,""); print $$1}')
RPM_GITHASH := $(shell git rev-parse --short HEAD)

%.spec: %.spec.in .FORCE
	sed -e 's/@@VERSION@@/$(RPM_VERSION)/g' \
	    -e 's/@@GITHASH@@/$(RPM_GITHASH)/g' < $< > $@+
	mv $@+ $@

TARFILE = scoutfs-utils-$(RPM_VERSION).tar

#
# make a stand alone buildable tarball for packaging, arguably this
# shouldn't be included in the dist Makefile :)
#
dist: $(RPM_DIR) scoutfs-utils.spec
	git archive --format=tar --prefix scoutfs-utils-$(RPM_VERSION)/ HEAD^{tree} > $(TARFILE)
	tar rf $(TARFILE) --transform="s@\(.*\)@scoutfs-utils-$(RPM_VERSION)/\1@" scoutfs-utils.spec
	tar rf $(TARFILE) --transform="s@.*\(src/.*\)@scoutfs-utils-$(RPM_VERSION)/\1@" $(FMTIOC_KMOD)

clean:
	@rm -f $(BIN) $(OBJ) $(DEPS) .sparse.*
