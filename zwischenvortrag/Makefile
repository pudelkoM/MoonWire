# The grand unified latex makefile
# or
# building latex is easy

# (2016) Johannes Naab <naab@net.in.tum.de>
# Originally based on work by
# Stephan Günther <guenther@tum.de>
# Maximilian Riemensberger <riemensberger@tum.de>

# Approach for dependency tracking taken from https://github.com/shiblon/latex-makefile
# Concept for fix point iteration on input files by https://github.com/aclements/latexrun

# extension and configuration go into Makefile.conf.mk

# All hope abandon ye who enter here

VERSION = 20160524.0

# make feature flags
.SECONDARY:

.SILENT :
.SECONDEXPANSION:

# output-sync supported since 4.0, which is not in OS X
# version check from https://lists.gnu.org/archive/html/help-make/2006-04/msg00065.html
# disabling built-in rules and variables only works properly since 4.0
ifeq (4.0,$(firstword $(sort $(MAKE_VERSION) 4.0)))
	MAKEFLAGS += -r -R -Oline
endif

FIGUREDIR := figures
BUILDDIR := build
.DEFAULT_GOAL := all

CURDIRBASE := $(notdir $(CURDIR))
RELEASE_FILENAME := $(CURDIRBASE).tar.gz

PDFLATEX ?= pdflatex
BIBTEX ?= bibtex
DIFF ?= diff
GREP ?= grep
AWK ?= awk
LS ?= ls
MV ?= mv
SED ?= sed
UNIQ ?= uniq
SORT ?= sort
FIND ?= find
TAR ?= tar
OPENSSL ?= openssl
CMP ?= cmp
XARGS ?= xargs

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

-include Makefile.conf.mk

PDFLATEX_FLAGS += -interaction=batchmode -recorder -file-line-error
GREP_FLAGS += -E -B 2 -A 3

TEXINPUTS := .:$(CURDIR):$(TEXINPUTS)
export TEXINPUTS

FIGURESTEXSRC += $(filter-out $(SKIP),$(wildcard $(FIGUREDIR)/*.tex))
FIGURESTEXPDF := $(FIGURESTEXSRC:.tex=.pdf)
FIGURESTIKZSRC += $(filter-out $(SKIP),$(wildcard $(FIGUREDIR)/*.tikz))
FIGURESTIKZPDF := $(filter-out $(FIGURESTEXPDF),$(FIGURESTIKZSRC:.tikz=.pdf))
FIGURESRC := $(FIGURESTEXSRC) $(FIGURESTIKZSRC)
FIGUREPDF := $(FIGURESTEXPDF) $(FIGURESTIKZPDF)

ALLFIGURESTIKZPDF := $(FIGURESTIKZPDF)
ALLFIGURESTEXPDF := $(FIGURESTEXPDF)

FIGURESUBDIRS := $(wildcard $(FIGUREDIR)/*/)
FIGURESUBDIRSTEMS := $(FIGURESUBDIRS:$(FIGUREDIR)/%/=%)

define template_FIGURESPDF
 FIGURESTEXSRC_$(1) += $$(filter-out $$(SKIP),$$(wildcard $$(FIGUREDIR)/$(1)/*.tex))
 FIGURESTEXPDF_$(1) := $$(FIGURESTEXSRC_$(1):.tex=.pdf)
 FIGURESTIKZSRC_$(1) += $$(filter-out $$(SKIP),$$(wildcard $$(FIGUREDIR)/$(1)/*.tikz))
 FIGURESTIKZPDF_$(1) := $$(filter-out $$(FIGURESTEXPDF_$(1)),$$(FIGURESTIKZSRC_$(1):.tikz=.pdf))
 FIGURESPDF_$(1) := $$(FIGURESTEXPDF_$(1)) $$(FIGURESTIKZPDF_$(1))
endef

$(foreach X,$(FIGURESUBDIRSTEMS),$(eval $(call template_FIGURESPDF,$(X))))
$(eval ALLFIGURESTEXPDF += $(FIGURESUBDIRSTEMS:%=$$(FIGURESTEXPDF_%)))
$(eval ALLFIGURESTIKZPDF += $(FIGURESUBDIRSTEMS:%=$$(FIGURESTIKZPDF_%)))
$(eval ALLFIGURESSRC += $(FIGURESUBDIRSTEMS:%=$(FIGURESTEXSRC_%)) $(FIGURESUBDIRSTEMS:%=$(FIGURESTIKZSRC_%)))

ALLFIGURESPDF := $(ALLFIGURESTEXPDF) $(ALLFIGURESTIKZPDF)

# studentdefs.tex itself does not build a pdf
TEXSRC := $(filter-out $(SKIP),$(wildcard *.tex))
TEXPDF := $(TEXSRC:.tex=.pdf)

# allow building protocol instead of protocol.pdf
TEXSTEM := $(TEXSRC:.tex=)

ALLTEXPDF := $(TEXPDF) $(ALLFIGURESPDF) $(SPECIALTEXPDF)

# only include (re-)buildable dependencies
DEPSMAKEINCLUDE := $(ALLTEXPDF:%=$(BUILDDIR)/%.d)
DEPSMAKEINCLUDEEXIST := $(wildcard $(DEPSMAKEINCLUDE))

DEPSMAKE  := $(filter-out $(DEPSMAKEINCLUDE),$(MAKEFILE_LIST))
DEPS      += $(DEPSMAKE)

# include dependency makefiles, but only if they exist (wildcard LIST)
# in order to force creation/update if *.d was deleted
$(DEPSMAKEINCLUDEEXIST): ;
include $(DEPSMAKEINCLUDEEXIST)

# debugging helper
# based on http://www.cmcrossroads.com/article/printing-value-makefile-variable
print-%:
	$(warning $*=$($*) ($(value $*)))

# http://www.cmcrossroads.com/article/dumping-every-makefile-variable
.PHONY: printvars
printvars:
	@$(foreach V, $(sort $(.VARIABLES)), $(if $(filter-out environment% default automatic, $(origin $V)), $(warning $V=$($V) ($(value $V)))))

# since empty include targets are not remade, create empty dependency includes
# https://www.gnu.org/software/make/manual/html_node/Remaking-Makefiles.html#Remaking-Makefiles
$(BUILDDIR)/%.d: MAGIC
	mkdir -p $(dir $@)
	touch $@

.PHONY: MAGIC
MAGIC:


# messaging functions
msgpdfstart = printf "building "$(BOLD)"%s"$(NOCOLOR)" from %s%s\n" "$(2)" "$(1)" "$(if $(3), -jobname=$(3))"
msgtarget = printf $(GREEN)"%s"$(MAGENTA)" %s"$(NOCOLOR)"\n" "$(1)" "$(2)"
msgcompile = printf $(BOLD)"%s"$(NOCOLOR)" %s from %s\n" "[$(1)]" "$(4)" "$(2)$(if $(3), -jobname $(3))"
msgfail = printf $(RED)"%s"$(NOCOLOR)" using %s %s "$(RED)"FAILED!"$(NOCOLOR)"\n" "$(4)" "$(1)" "$(2)$(if $(3), -jobname $(3))"

# $(1) document
# $(2) jobname
# $(3) output-directory
# $(4) target (for logging)
define run-typeset
  $(call msgcompile,$(PDFLATEX),$(1),$(2),$(4)); \
  ( cd $(3) && $(PDFLATEX) $(PDFLATEX_FLAGS) $(if $(2),-jobname=$(2)) $(1) ) </dev/null >/dev/null 2>&1 || \
    { $(call msgfail,$(PDFLATEX),$(1),$(2),$(4)); false; }
endef

# $(1) aux file
# $(2) target (for logging)
define run-bibtex
  $(call msgcompile,$(BIBTEX),$(1),,$(2)); \
  $(BIBTEX) $(BIBTEX_FLAGS) $(1) </dev/null 1>/dev/null 2>&1 || \
    { $(call msgfail,$(BIBTEX),$(1),,$(2)); false; }
endef

# $(1) log file
# $(2) target (for reference)
define extract-log
  printf "Extracting log for "$(MAGENTA)"%s"$(NOCOLOR)" from "$(GREEN)"%s"$(NOCOLOR)"\n" "$(2)" "$(1)"; \
  $(GREP) -E -v -e "^<Error-correction level increased from . to . at no cost\\.>$$" $(1) | \
  $(GREP) $(GREP_FLAGS) -e ":[[:digit:]]+: |Warning|Error|Underfull|Overfull|\!|Reference|Label|Citation" || :
endef

# $(call get-inputs,<jobname>,<target>)
# $(1) outstem
# $(2) document
define get-inputs
$(AWK) 'BEGIN { rel="$(CURDIR)"; if (rel !~ /\/$$/) {rel = rel "/"}; target="$(2)"; gsub(" ","\\\\ ",target); } \
/^PWD / {path=substr($$0,5) "/"} \
/^INPUT / { \
	f=substr($$0,7); \
	if (f ~ /^\.\//) {f=path substr(f,3)}; \
	if (f !~ /^\//) {f=path f}; \
	sub(rel,"",f); \
	if (f !~ /\%/ && f != "/dev/null") { all[f] }\
} END { for (i in all) {gsub(" ", "\\\\ ",i); print target ": " i; print i ":";} }' $(1).fls |\
sort
endef

# $(1) foo.fls
# $(2) outputdir
define check-inputs
{ echo $1.nav; echo $1.snm; echo $1.out; $(AWK) '/^INPUT / { print substr($$0,7) }' $1.fls; } | sort -u | $(XARGS) $(OPENSSL) sha512 2>/dev/null
endef

# $(1) outstem
# $(2) target
define get-bib-inputs
$(SED) -n 's!^\\bibdata{\(.*\)}$$!\1.bib!p' $(1).aux | \
$(SORT) -u | \
$(AWK) '{ print "$2: "p$$0; print p$$0":"; }'
endef

# $(1) document
# $(2) jobname
define getjobstem
$(if $(2),$(2),$(basename $(notdir $(1))))
endef

# $(1) document, required
# $(2) jobname
# $(3) builddir, if set this is used directly, else the build dir is constructed based on $(BUILDDIR), document and jobname
define getbuilddir
$(if $(3),$(3),$(BUILDDIR)/$(1)/$(call getjobstem,$(1),$(2)))
endef

# $(1) document, required
# $(2) jobname
# $(3) output
define getoutstem
$(call getbuilddir,$(1),$(2),$(3))/$(call getjobstem,$(1),$(2))
endef

# $(1) doc, required
# $(2) out, required
# $(3) jobname, can be empty
# $(4) outdir, required
# $(5) outstem, required
define pdfbuilderexpsinglepass
$(call run-typeset,$(1),$(3),$(4),$(2)) || touch $(4).error ; \
$(AWK) '/^\\bibdata{/{b=1}END{if (b) {exit 1} else {exit 0}}' $(5).aux || { $(call run-bibtex,$(5).aux,$(2)) || touch $(4).error ; } ;\
( cd $(4) && $(call check-inputs,$(notdir $(5))) ) > $(4).inputs.new ;\
cmp -s $(4).inputs.new $(4).inputs || { \
mv $(4).inputs.new $(4).inputs ;\
} ;
endef

# $(1) doc, required
# $(2) out, required
# $(3) jobname, can be empty
# $(4) outdir, required
# $(5) outstem, required
define pdfbuilderexpsinglepasstry
test -e $(4).inputs.new || { $(call pdfbuilderexpsinglepass,$(1),$(2),$(3),$(4),$(5)) } ;
endef

# $(1) doc, required
# $(2) out, required
# $(3) jobname, can be empty
# $(4) outdir, required
# $(5) outstem, required
# concept of fix point iteration taken from https://github.com/aclements/latexrun
# ideally we would set .DELETE_ON_ERROR, but this would break any preview
# so we roll our own error handling with $(4).error
define pdfbuilderexp
$(call msgpdfstart,$(1),$(2),$(3))
mkdir -p $(4)
rm -rf $(4).error
( test -e $(5).fls && cd $(4) && $(call check-inputs,$(notdir $(5))) ) > $(4).inputs || true
$(call pdfbuilderexpsinglepass,$(1),$(2),$(3),$(4),$(5))
$(call pdfbuilderexpsinglepasstry,$(1),$(2),$(3),$(4),$(5))
$(call pdfbuilderexpsinglepasstry,$(1),$(2),$(3),$(4),$(5))
$(call pdfbuilderexpsinglepasstry,$(1),$(2),$(3),$(4),$(5))
$(call pdfbuilderexpsinglepasstry,$(1),$(2),$(3),$(4),$(5))
test -e $(4).inputs.new || printf $(RED)"%s"$(NOCOLOR)": "$(BOLD)"fix point iteration failed"$(NOCOLOR)"\n" "$(2)"
$(call extract-log,$(5).log,$(2))
$(call get-inputs,$(5),$@) > $(BUILDDIR)/$@.d
$(call get-bib-inputs,$(5),$@) >> $(BUILDDIR)/$@.d
test -e $(4).error || touch -r $(BUILDDIR)/$@.d $(5).pdf
mkdir -p $(dir $(2))
$(MV) $(5).pdf $(2)
test ! -e $(4).error
endef

# $(1) doc, required
# $(2) out, required
# $(3) jobname
# $(4) builddir
define pdfbuilder
$(call pdfbuilderexp,$(1),$(2),$(3),$(call getbuilddir,$(1),$(3),$(4)),$(call getoutstem,$(1),$(3),$(4)))
endef

.PHONY: $(TEXSTEM)
$(TEXSTEM): %: %.pdf ;

# target for directly build documents without jobname
$(filter-out $(ALLFIGURESPDF),$(ALLTEXPDF)): $(FIGUREPDF)
$(filter-out $(ALLFIGURESTIKZPDF) $(SPECIALTEXPDF),$(ALLTEXPDF)): %.pdf: %.tex $$(DEPS_$$*) $$(FIGURESPDF_$$*) $(DEPS) $(BUILDDIR)/$$@.d
	$(call pdfbuilder,$<,$@)

# use hard coded for shell completion
.PHONY: $(FIGUREDIR)
$(FIGUREDIR): $(ALLFIGURESPDF)

# tikz figures, other figures are built by generic *.pdf target
$(ALLFIGURESTIKZPDF): %.pdf: %.tikz $$(DEPS_$$*) $(DEPS) $(BUILDDIR)/$$@.d
	$(call pdfbuilder,$<,$@)

.PHONY: all
all: $(ALLTEXPDF)

.PHONY : clean cleanall
clean:
	rm -fv $(DEPSMAKEINCLUDE)
	rm -rfv $(addprefix $(BUILDDIR)/,$(FIGURESRC) $(TEXSRC) $(ALLFIGURESSRC))

cleanall: clean
	rm -fv $(ALLTEXPDF)
	rm -rfv $(BUILDDIR)/

.PHONY: release $(RELEASE_FILENAME)
$(RELEASE_FILENAME): cleanall
	cd .. \
		&& $(FIND) "$(CURDIRBASE)" ! -path "$(CURDIRBASE)" ! -path "$(CURDIRBASE)/$@" -print0 \
		| $(TAR) -cvzf "$(CURDIRBASE)/$@" -h --null -T -

release: $(RELEASE_FILENAME)
