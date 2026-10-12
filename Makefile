# Makefile for kl
# Standard POSIX wrapper that awk-parses recipes directly from Justfile.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.ONESHELL:

JOBS ?= 2

export JOBS

JUST := $(shell command -v just 2>/dev/null)

# Discover available recipe names from Justfile (excluding help and default)
TARGETS := $(shell awk '(/^[a-zA-Z0-9_-]+ *:[^=]/ || /^[a-zA-Z0-9_-]+ *:$$/) && !/^[a-zA-Z0-9_-]+ *:=/ { split($$1, a, ":"); t = a[1]; if (t != "help" && t != "default") print t }' Justfile 2>/dev/null)

.PHONY: $(TARGETS) help default

define AWK_PARSER
BEGIN {
    vars["jobs"] = jobs
}
# Capture variable definitions: var := "val"
/^[a-zA-Z0-9_-]+ *:=/ {
    var = $$1
    val = $$0
    sub(/^[a-zA-Z0-9_-]+ *:= *"/, "", val)
    sub(/".*$$/, "", val)
    if (!(var in vars)) vars[var] = val
    next
}
# Capture doc comment above recipe
/^# / {
    sub(/^# */, "")
    last_doc = $$0
    next
}
# Capture recipe signature
(/^[a-zA-Z0-9_-]+ *:[^=]/ || /^[a-zA-Z0-9_-]+ *:$$/) && !/^[a-zA-Z0-9_-]+ *:=/ {
    curr = $$1
    sub(/:.*/, "", curr)
    header = $$0
    sub(/^[a-zA-Z0-9_-]+ *: */, "", header)
    deps[curr] = header
    all_targets[curr] = 1
    doc[curr] = last_doc
    order[++target_count] = curr
    last_doc = ""
    next
}
# Capture recipe body lines and interpolate variables
/^[ \t]+/ && curr != "" {
    line = $$0
    sub(/^[ \t]+/, "", line)
    for (v in vars) {
        gsub("\\{\\{ *" v " *\\}\\}", vars[v], line)
    }
    gsub(/[$$][$$]/, "$$", line)
    body[curr] = (body[curr] ? body[curr] "\n" : "") line
    next
}
!/^[ \t]/ {
    curr = ""
    last_doc = ""
}
function emit(t,    n, d, i, k, lines, cmd) {
    if (!(t in all_targets)) {
        print "echo \"error: unknown recipe: " t "\" >&2; exit 1"
        return
    }
    if (deps[t] != "") {
        n = split(deps[t], d, " ")
        for (i = 1; i <= n; i++) {
            if (d[i] != "") emit(d[i])
        }
    }
    if (body[t] != "") {
        k = split(body[t], lines, "\n")
        for (i = 1; i <= k; i++) {
            cmd = lines[i]
            sub(/^@/, "", cmd)
            print cmd
        }
    }
}
function show_help() {
    print "Usage: make <target>"
    print ""
    print "Available recipes (parsed from Justfile):"
    for (i = 1; i <= target_count; i++) {
        t = order[i]
        if (t != "default" && t != "help") {
            printf "  \033[36m%-24s\033[0m %s\n", t, (doc[t] ? doc[t] : "")
        }
    }
}
END {
    if (target == "help" || target == "default" || target == "") {
        show_help()
    } else {
        print "set -euo pipefail"
        emit(target)
    }
}
endef
export AWK_PARSER

help:
	@if [ -n "$(JUST)" ]; then \
		$(JUST) --list; \
	else \
		awk -v target="help" -v jobs="$(JOBS)" "$$AWK_PARSER" Justfile; \
	fi

default: help

$(TARGETS):
	@if [ -n "$(JUST)" ]; then \
		$(JUST) --set jobs "$(JOBS)" "$@"; \
	else \
		awk -v target="$@" -v jobs="$(JOBS)" "$$AWK_PARSER" Justfile | $(SHELL); \
	fi

%:
	@if [ -n "$(JUST)" ]; then \
		$(JUST) --set jobs "$(JOBS)" "$*"; \
	else \
		awk -v target="$*" -v jobs="$(JOBS)" "$$AWK_PARSER" Justfile | $(SHELL); \
	fi
