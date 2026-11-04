SEMGREP_OPTS = --metrics off --disable-version-check

.PHONY: help rules test recall scan discover clean hunt
help:
	@echo "make rules     regenerate rules from tools/gen_rules.py"
	@echo "make test      unit-test every rule against tests/ fixtures"
	@echo "make recall    re-find 5 published MCP CVEs/advisories at their vulnerable versions"
	@echo "make discover  build repos.txt (GitHub + npm)"
	@echo "make scan      scan repos.txt -> hunter-scan/{findings.csv,repos.csv,summary.md}"
	@echo "make hunt      scan one server: make hunt DIR=path-or-owner/repo"

rules:
	python3 tools/gen_rules.py

test:
	semgrep --test --config rules/ tests/ $(SEMGREP_OPTS)

recall:
	bash bench/recall.sh

discover:
	python3 src/discover.py -o repos.txt

scan:
	python3 src/scan.py repos.txt

clean:
	rm -rf .recall hunter-scan

hunt:
	@[ -n "$(DIR)" ] || { echo "usage: make hunt DIR=path-or-owner/repo"; exit 2; }
	python3 src/hunt.py $(DIR)
