"""
CAPSTONE 75 — Sensitive Information Prompt Checker
Educational demo: flags likely email addresses, phone-like numbers,
sensitive ID labels, and credential/secret keywords.
This script scans a local text file; it does not upload content anywhere.
It is not a complete security or data-loss-prevention tool.
"""
import re
import sys
from pathlib import Path

PATTERNS = [
    ("Possible email address", re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("Possible phone number", re.compile(
        r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}(?!\w)")),
    ("Sensitive ID label", re.compile(
        r"\b(?:student|registration|employee|customer|account|passport|national)\s*(?:id|number|no\.?)\b",
        re.IGNORECASE)),
    ("Credential/secret keyword", re.compile(
        r"\b(?:api[_ -]?key|password|passwd|secret|access[_ -]?token|private[_ -]?key)\b",
        re.IGNORECASE)),
    ("Possible secret assignment", re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token|secret|password)\s*[:=]\s*\S+",
        re.IGNORECASE)),
]

def scan_text(text):
    results = []
    for label, pattern in PATTERNS:
        matches = list(pattern.finditer(text))
        if matches:
            lines = sorted({text.count("\n", 0, m.start()) + 1 for m in matches})
            results.append((label, len(matches), lines))
    return results

def main():
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1])
        try:
            text = input_file.read_text(encoding="utf-8")
        except OSError as error:
            print(f"ERROR: Cannot read input file: {error}")
            sys.exit(1)
    else:
        print("Paste text to scan. Finish with Ctrl+Z then Enter on Windows.")
        text = sys.stdin.read()

    findings = scan_text(text)
    print("CAPSTONE 75 — Sensitive Information Prompt Checker")
    print("Local scan only: text is not sent to an online service.")
    print("-" * 58)
    if not findings:
        print("No patterns flagged. This does NOT prove the text is safe.")
    else:
        print(f"Flagged {len(findings)} pattern categories:")
        for label, count, lines in findings:
            print(f"- {label}: {count} match(es), line(s): {', '.join(map(str, lines))}")
        print("\nACTION: Review the source text and remove unnecessary sensitive values.")
    print("\nLimitations: false positives and missed patterns are possible.")
    print("Do not use this tool as a guarantee that text is safe.")

if __name__ == "__main__":
    main()
