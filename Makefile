#
# Typically development is done in each subdir, but we have a tiny
# makefile here to make it easy to run simple targets across all the
# subdirs.
#

SUBDIRS := kmod utils tests
NOTTESTS := kmod utils

all clean: $(SUBDIRS) FORCE
dist: $(NOTTESTS) FORCE

$(SUBDIRS): FORCE
	$(MAKE) -C $@ $(MAKECMDGOALS)

all:
FORCE:
