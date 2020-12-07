#
# # dnf install latexmk texlive
# # make
#
# Tools
LATEXMK = latexmk
RM = rm -f

# Project-specific settings
DOCNAME = scoutfs

# Targets
all: doc
doc: pdf
pdf: $(DOCNAME).pdf

# Rules
%.pdf: %.tex
	$(LATEXMK) -pdf -M -MP -MF $*.d $*

mostlyclean:
	$(LATEXMK) -silent -c
	$(RM) *.bbl

clean: mostlyclean
	$(LATEXMK) -silent -C
	$(RM) *.run.xml *.synctex.gz
	$(RM) *.d

.PHONY: all clean doc mostlyclean pdf

# Include auto-generated dependencies
-include *.d
