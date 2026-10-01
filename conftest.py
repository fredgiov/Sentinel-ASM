"""Pytest plugin: prints every test result inside one neat box.

Applies automatically to every test function in the project. For each test it
shows the class it belongs to, its name, PASS/FAIL, and for failures the line
number in the test file plus where the error was actually raised.
"""

import os
import textwrap

import pytest

WIDTH = 100
INNER = WIDTH - 4  # room for "│ " and " │"

_results = []


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    # The box replaces pytest's long failure listing and its final summary line.
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter:
        reporter.summary_failures = lambda: None
        reporter.summary_errors = lambda: None
        reporter.short_test_summary = lambda: None
        reporter.summary_stats = lambda: None


def pytest_report_teststatus(report, config):
    # Silence pytest's own dots/names; the box below replaces them.
    if report.when == "call" or (report.when == "setup" and report.failed):
        return report.outcome, "", ""
    return None


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and report.failed):
        _results.append(report)


def _failure_details(report):
    """Return (test_line, crash_location, message_lines) for a failed report."""
    crash = report.longrepr.reprcrash
    test_file = report.nodeid.split("::")[0]
    test_line = None
    for entry in report.longrepr.reprtraceback.reprentries:
        loc = getattr(entry, "reprfileloc", None)
        if loc and os.path.basename(loc.path) == os.path.basename(test_file):
            test_line = loc.lineno  # first frame in the test file = the test body itself
            break
    where = f"{os.path.relpath(crash.path)}:{crash.lineno}"
    return test_line, where, crash.message.splitlines()


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    tr = terminalreporter
    if not _results:
        return

    def row(text="", **markup):
        tr.write_line(f"│ {text.ljust(INNER)} │", **markup)

    def wrapped(prefix, text, **markup):
        for n, chunk in enumerate(textwrap.wrap(text, INNER - len(prefix)) or [""]):
            row((prefix if n == 0 else " " * len(prefix)) + chunk, **markup)

    passed = sum(r.passed for r in _results)
    failed = sum(r.failed for r in _results)
    skipped = sum(r.skipped for r in _results)

    tr.write_line("")
    tr.write_line("┌" + "─" * (WIDTH - 2) + "┐")
    row("DISASSEMBLER TEST REPORT".center(INNER), bold=True)
    tr.write_line("├" + "─" * (WIDTH - 2) + "┤")

    current_group = None
    for report in _results:
        parts = report.nodeid.split("::")
        group = parts[1] if len(parts) > 2 else "(module)"
        name = parts[-1]
        if group != current_group:
            if current_group is not None:
                row()
            row(group, bold=True)
            current_group = group

        if report.passed:
            row(f"  ✔ PASS  {name}", green=True)
        elif report.skipped:
            row(f"  ○ SKIP  {name}", yellow=True)
        else:
            row(f"  ✘ FAIL  {name}", red=True, bold=True)
            test_line, where, message = _failure_details(report)
            if test_line:
                row(f"          failed at {os.path.basename(report.nodeid.split('::')[0])}:{test_line}", red=True)
            row(f"          raised at {where}", red=True)
            for line in message[:6]:
                wrapped("          ", line, red=True)

    tr.write_line("├" + "─" * (WIDTH - 2) + "┤")
    summary = f"{passed} passed   {failed} failed   {skipped} skipped   ({len(_results)} total)"
    row(summary.center(INNER), green=failed == 0, red=failed > 0, bold=True)
    tr.write_line("└" + "─" * (WIDTH - 2) + "┘")
