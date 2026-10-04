# The PoC needs only Python; draft authoring tools are separate.
PYTHON ?= python3
KRAMDOWN_RFC ?= kramdown-rfc
XML2RFC ?= xml2rfc
DRAFT = draft-chen-cfrg-pqpake-authentication-00
DATE := $(shell sed -n 's/^date: //p' $(DRAFT).md)
OUT = rendered

.PHONY: all draft test
all: draft

test:
	$(PYTHON) protocol_harness.py

draft:
	mkdir -p $(OUT)
	$(KRAMDOWN_RFC) --v3 $(DRAFT).md > $(OUT)/.raw.xml
	$(XML2RFC) $(OUT)/.raw.xml --v2v3 --out $(OUT)/.v3.xml --date $(DATE) --skip-config-files
	$(PYTHON) -c 'from pathlib import Path; import re; s = Path("$(OUT)/.v3.xml").read_text(); s = re.sub(r"<\?line\s+\d+\s*\?>", "", s); s = re.sub(r"<!-- ##markdown-source:.*?-->", "", s, flags=re.S); Path("$(OUT)/$(DRAFT).xml").write_text(s)'
	$(XML2RFC) $(OUT)/$(DRAFT).xml --v3 --text --html --date $(DATE) --skip-config-files
	rm -f $(OUT)/.raw.xml $(OUT)/.v3.xml
