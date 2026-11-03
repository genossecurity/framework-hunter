SEMGREP_OPTS = --metrics off --disable-version-check

.PHONY: help rules test recall scan discover clean
help:
	@echo "make rules     regenerate rules from tools/gen_rules.py"
	@echo "make test      unit-test every rule against tests/ fixtures"
	@echo "make recall    re-find 3 published MCP CVEs at their vulnerable versions"
	@echo "make discover  build repos.txt (GitHub + npm)"
	@echo "make scan      scan repos.txt -> mcp-scan/{findings.csv,repos.csv,summary.md}"

rules:
	python3 tools/gen_rules.py

test:
	semgrep --test --config rules/ tests/ $(SEMGREP_OPTS)

recall:
	bash bench/recall.sh

discover:
	python3 discover.py -o repos.txt

scan:
	python3 scan.py repos.txt

clean:
	rm -rf .recall mcp-scan

hunt:
	@[ -n "$(DIR)" ] || { echo "usage: make hunt DIR=path-or-owner/repo"; exit 2; }
	python3 hunt.py $(DIR)
