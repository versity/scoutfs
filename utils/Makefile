SCOUTFS_FORMAT_HASH := \
	$(shell cat src/format.h src/ioctl.h | md5sum | cut -b1-16)

CFLAGS := -Wall -O2 -Werror -D_FILE_OFFSET_BITS=64 -g -msse4.2 \
	-Wpadded \
	-fno-strict-aliasing \
	-DSCOUTFS_FORMAT_HASH=0x$(SCOUTFS_FORMAT_HASH)LLU

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
	$(VE)gcc -o $@ $^ -luuid -lm -lcrypto

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

dist: $(RPM_DIR) scoutfs-utils.spec
	git archive --format=tar --prefix scoutfs-utils-$(RPM_VERSION)/ HEAD^{tree} > $(TARFILE)
	@ tar rf $(TARFILE) --transform="s@\(.*\)@scoutfs-utils-$(RPM_VERSION)/\1@" scoutfs-utils.spec

clean:
	@rm -f $(BIN) $(OBJ) $(DEPS) .sparse.*
