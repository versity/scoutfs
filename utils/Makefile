CFLAGS := -Wall -O2 -Werror -D_FILE_OFFSET_BITS=64 -g -mrdrnd -msse4.2

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
	$(VE)gcc -o $@ $^ -luuid -lm

%.o %.d: %.c Makefile sparse.sh
	$(QU)  [CC $<]
	$(VE)gcc $(CFLAGS) -MD -MP -MF $*.d -c $< -o $*.o
	$(QU)  [SP $<]
	$(VE)./sparse.sh -Wbitwise -D__CHECKER__ $(CFLAGS) $<

.PHONY: clean
clean:
	@rm -f $(BIN) $(OBJ) $(DEPS) .sparse.*
