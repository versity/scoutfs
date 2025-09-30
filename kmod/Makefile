ALL: module

# default to building against the installed source for the running kernel
ifeq ($(SK_KSRC),)
SK_KSRC := $(shell echo /lib/modules/`uname -r`/build)
endif

SCOUTFS_GIT_DESCRIBE ?= \
	$(shell git describe --all --abbrev=6 --long 2>/dev/null || \
		echo no-git)

ESCAPED_GIT_DESCRIBE := \
	$(shell echo $(SCOUTFS_GIT_DESCRIBE) |sed -e 's/\//\\\//g')

RPM_GITHASH ?= $(shell git rev-parse --short HEAD)

SCOUTFS_ARGS := SCOUTFS_GIT_DESCRIBE=$(SCOUTFS_GIT_DESCRIBE) \
		RPM_GITHASH=$(RPM_GITHASH) \
		CONFIG_SCOUTFS_FS=m -C $(SK_KSRC) M=$(CURDIR)/src \
		EXTRA_CFLAGS="-Werror"

# - We use the git describe from tags to set up the RPM versioning
RPM_VERSION := $(shell git describe --long --tags | awk -F '-' '{gsub(/^v/,""); print $$1}')
TARFILE = scoutfs-kmod-$(RPM_VERSION).tar


.PHONY: .FORCE

all: module

module:
	$(MAKE) CHECK=$(CURDIR)/src/sparse-filtered.sh C=1 CF="-D__CHECK_ENDIAN__" $(SCOUTFS_ARGS)

modules_install:
	$(MAKE) $(SCOUTFS_ARGS) modules_install


%.spec: %.spec.in .FORCE
	sed -e 's/@@VERSION@@/$(RPM_VERSION)/g' \
	    -e 's/@@GITHASH@@/$(RPM_GITHASH)/g' \
	    -e 's/@@GITDESCRIBE@@/$(ESCAPED_GIT_DESCRIBE)/g' < $< > $@+
	mv $@+ $@


dist: scoutfs-kmod.spec
	git archive --format=tar --prefix scoutfs-kmod-$(RPM_VERSION)/ HEAD^{tree} > $(TARFILE)
	@ tar rf $(TARFILE) --transform="s@\(.*\)@scoutfs-kmod-$(RPM_VERSION)/\1@" scoutfs-kmod.spec

clean:
	$(MAKE) $(SCOUTFS_ARGS) clean
