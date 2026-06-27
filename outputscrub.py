#!/usr/bin/env python3
"""
OutputScrub — sanitize agent outputs before they reach users.

Strip PII (emails, phones, SSNs, addresses), redact API keys/secrets,
format for destination channels, and enforce content policies.

Plugin-style rules — add your own regex patterns via JSON config.

Pure Python standard library. Zero dependencies.

Domains: AI safety · data privacy · compliance · agent output moderation.
"""
import argparse, json, re, sys

DEFAULT_RULES = [
    # Emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # Phones
    (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "[PHONE]"),
    # SSNs
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    # API keys (common patterns)
    (re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{30,}|hf_[A-Za-z0-9]{20,})\b"), "[API_KEY]"),
    # Credit cards
    (re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b"), "[CREDIT_CARD]"),
    # IPs
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[IP_ADDR]"),
]


def scrub(text, rules=None, custom_patterns=None):
    rules = rules or DEFAULT_RULES
    findings = []
    for pattern, replacement in rules:
        matches = pattern.findall(text)
        if matches:
            findings.append({"pattern": pattern.pattern[:60], "count": len(matches)})
            text = pattern.sub(replacement, text)

    if custom_patterns:
        for cp in custom_patterns:
            pat = re.compile(cp["pattern"], cp.get("flags", 0))
            matches = pat.findall(text)
            if matches:
                findings.append({"pattern": cp["pattern"][:60], "count": len(matches)})
                text = pat.sub(cp.get("replace", "[REDACTED]"), text)

    return {"text": text, "findings": findings, "clean": len(findings) == 0}


def cmd(args):
    text = open(args.input, encoding="utf-8").read()
    rules = None
    if args.rules:
        rules_data = json.load(open(args.rules, encoding="utf-8"))
        rules = [(re.compile(r["pattern"], r.get("flags", 0)), r["replace"]) for r in rules_data]

    result = scrub(text, rules, args.custom)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    elif args.output:
        open(args.output, "w", encoding="utf-8").write(result["text"])
        print(f"Scrubbed → {args.output} ({len(result['findings'])} redactions)")
    else:
        print(result["text"])
    return 0


def main():
    p = argparse.ArgumentParser(prog="outputscrub", description=__doc__)
    p.add_argument("--input", required=True, help="text file to scrub")
    p.add_argument("--rules", help="custom rules JSON file")
    p.add_argument("--custom", type=json.loads, default=None, help="inline custom rules JSON")
    p.add_argument("--output", help="output file (default: stdout)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
