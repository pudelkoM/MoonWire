.SILENT :
.PHONY  : all

# Makefile.inc should only include the document's main tex file and the target
# name, e.g.
# DOCUMENT := slides.tex
# TARGET := slides
include Makefile.inc

DOCUMENT += $(wildcard include/*.tex)
FIGURES  := figures
CURDIRBASE := $(notdir $(CURDIR))
RELEASE_FILENAME := $(CURDIRBASE).tar.gz

PDFLATEX ?= $(shell which pdflatex)
BIBTEX ?= $(shell which bibtex)
DIFF ?= $(shell which diff)
FIND ?= $(shell which find)
GREP ?= $(shell which grep)
AWK ?= $(shell which awk)
MKDIR ?= $(shell which mkdir)
TOUCH ?= $(shell which touch)
TAR ?= $(shell which tar)
RM ?= $(shell which rm)
RMDIR ?= $(shell which rmdir)

PDFLATEX_FLAGS	:= -interaction=nonstopmode
GREP_FLAGS += -E -B 0 -A 2

# terminal colors
ifneq ($(COLORTERM),false)
  NOCOLOR := "\033[0m"
  RED := "\033[1;31m"
  BLUE := "\033[1;34m"
  GREEN := "\033[1;32m"
  YELLOW := "\033[1;33m"
  CYAN := "\033[1;36m"
  WHITE := "\033[1;37m"
  MAGENTA := "\033[1;35m"
  BOLD := "\033[1m"
else
  NOCOLOR := ""
  RED := ""
  BLUE := ""
  GREEN := ""
  YELLOW := ""
  CYAN := ""
  WHITE := ""
  MAGENTA := ""
  BOLD := ""
endif

# helper functions for filename conversion
getname = $(firstword $(subst ., ,$(1)))
getaux = $(call getname,$(1)).aux

# messaging functions
msgtarget = printf $(GREEN)"%s"$(MAGENTA)" %s"$(NOCOLOR)"\n" "$(1)" "$(2)"
msgcompile = printf $(BOLD)"%-25s"$(NOCOLOR)" %s\n" "[$(1)]" "$(2)"
msgfail = printf "%-25s "$(RED)"%s"$(NOCOLOR)"\n" "" "FAILED! Continuing ..."
msginfo = printf "%-25s "$(CYAN)"%s"$(NOCOLOR)"\n" "" "$(1)"

define run-typeset
  $(call msgcompile,$(PDFLATEX),$(1)); \
  $(PDFLATEX) $(PDFLATEX_FLAGS) $(1) 1>/dev/null 2>&1 </dev/null || \
    $(call msgfail)
endef

define run-bibtex
  $(call msgcompile,$(BIBTEX),$(call getaux,$(1))); \
  $(BIBTEX) $(BIB_FLAGS) $(call getaux,$(1)) 1>/dev/null 2>&1 || \
    $(call msgfail)
endef

define grep-citation
  $(GREP) $(GREP_FLAGS) -e "Warning: Citation .*" \
    $(call getlog,$(1)) 1>/dev/null 2>&1
endef

define check-citation
  $(GREP) -e'^\\citation' $(call getaux,$(1)) 2>/dev/null \
    >$(call gettemp,$(1)); \
  $(DIFF) $(call gettemp,$(1)) $(call getcit,$(1)) 1>/dev/null 2>&1 || \
        (mv -f $(call gettemp,$(1)) $(call getcit,$(1)); false)
endef

define grep-crossref
  $(GREP) $(GREP_FLAGS) -e "Rerun to get .*" \
    $(call getlog,$(1)) 1>/dev/null 2>&1 && \
    $(call msginfo,Rerun latex to get everything right.)
endef

define extract-log
  $(call msgtarget,Extracting log file for target,$(1)); \
  $(GREP) $(GREP_FLAGS) \
	-e "Warning|Error|Underfull|Overfull|\!|Reference|Label|Citation" \
	$(call getname,$(1)).log || :
endef

all: $(TARGET).pdf

$(TARGET).pdf: $(DOCUMENT)
	if [ -f "$(FIGURES)/Makefile" ]; then \
		$(MAKE) -C $(FIGURES); \
	fi
	$(call run-typeset,$<)
	if [ -f "lit.bib" ]; then \
		$(call run-bibtex,$<); \
	fi
	$(call run-typeset,$<)
	$(call run-typeset,$<)
	$(call extract-log,$<)

clean:
	$(RM) -fv *.aux
	$(RM) -fv *.log
	$(RM) -fv *.toc
	$(RM) -fv *.lof
	$(RM) -fv *.lot
	$(RM) -fv *.eps
	$(RM) -fv *.bbl
	$(RM) -fv *.out
	$(RM) -fv *.fls
	$(RM) -fv *.blg
	$(RM) -fv *.auxlock
	$(RM) -fv *.nav
	$(RM) -fv *.snm
	if [ -f "$(FIGURES)/Makefile" ]; then \
		$(MAKE) -C $(FIGURES) clean; \
	fi

cleanall: clean
	$(RM) -fv $(TARGET).pdf
	if [ -f "$(FIGURES)/Makefile" ]; then \
		$(MAKE) -C $(FIGURES) cleanall; \
	fi
	$(RM) -fv $(RELEASE_FILENAME).tar.xz

$(RELEASE_FILENAME): cleanall $(DOCUMENT) $(COMMON) $(OTHERS)
	cd .. \
		&& $(FIND) "$(CURDIRBASE)" ! -path "$(CURDIRBASE)" ! -path "$(CURDIRBASE)/$@" -print0 \
		| $(TAR) -cvzf "$(CURDIRBASE)/$@" -h --null -T -

release: $(RELEASE_FILENAME)
