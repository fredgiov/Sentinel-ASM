# Python's answer to npm scripts. Run from the project root:
#   make install           install dependencies (like `npm install`)
#   make test-disassembly  run the disassembler tests (like `npm run test-disassembly`)
#   make help              list everything

PYTHON ?= python3

.PHONY: help install test test-disassembly clean

help:
	@echo "make install           install dependencies"
	@echo "make test-disassembly  run test_disassembler.py verbosely"
	@echo "make test              run all tests"
	@echo "make clean             remove __pycache__ folders"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test-disassembly:
	$(PYTHON) -m pytest test_disassembler.py

test:
	$(PYTHON) -m pytest

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
