# Self-documenting Make help.
# Targets annotated as `target: ## description` are listed automatically.

ESC    := \033
RESET  := $(ESC)[0m
YELLOW := $(ESC)[33m
CYAN   := $(ESC)[36m

MARVIN := Reluctantly administered by Marvin, the Paranoid Android
TITLE := MONAD FIREWALL — DEVELOPMENT DIAGNOSTICS

# Usage: $(call put,text,color)
define put
	@printf '%b%s%b\n' '$(2)' '$(1)' '$(RESET)'
endef

.PHONY: doctor help
.DEFAULT_GOAL := help

help: ## Consult this reassuringly short guide
	@printf '\n'
	$(call put,$(TITLE),$(CYAN))
	$(call put,$(MARVIN),$(YELLOW))
	@printf '\n'
	@awk 'BEGIN {FS = ":.*##"; printf "AVAILABLE TARGETS:\n"} \
		/^[a-zA-Z_-]+:.*##/ { \
			printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 \
		}' $(MAKEFILE_LIST)
	@printf '\n'

doctor: ## Discover what ails your environment
	@sh scripts/doctor.sh
