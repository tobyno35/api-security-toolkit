"""Command-line entry point and report rendering."""

import argparse
import json
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

from .assessment import InputError, assess


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    raise InputError(f"invalid JSON constant: {value}")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise InputError(f"{path}: {error}") from error


def markdown(report):
    lines = ["# API Security Assessment", "", "Synthetic evidence only.", "", "## Summary", "",
             "| Classification | Cases |", "| --- | ---: |"]
    lines.extend(f"| `{name}` | {count} |" for name, count in report["summary"].items())
    for case in report["cases"]:
        subject, resource = case["subject"], case["resource"]
        control_refs = ", ".join(f"`{ref}`" for ref in case["control_references"]) or "None"
        lines.extend([
            "", f"## `{case['id']}`", "",
            f"**`{case['classification']}`**. {case['reason']}", "",
            f"- Check and operation: `{case['check']}` on `{case['operation']}`.",
            f"- Subject: `{subject['id']}` (`{subject['role']}`, `{subject['tenant']}`).",
            f"- Resource: `{resource['id']}` (tenant `{resource['tenant']}`, "
            f"owner `{resource['owner'] or 'none'}`).",
            f"- Subject relation and policy: `{case['subject_relation']}`, "
            f"`{case['subject_expected'] or 'missing'}` (`{case['subject_rule_id'] or 'none'}`).",
            f"- Successful permitted controls: {control_refs}.",
        ])
        if case["observations"]:
            lines.extend([
                "", "| Evidence reference | Actor | Relation | Outcome | Policy |",
                "| --- | --- | --- | --- | --- |",
            ])
            for item in case["observations"]:
                policy = f"`{item['expected']}` (`{item['rule_id']}`)" if item["rule_id"] else "Missing"
                lines.append(
                    f"| `{item['ref']}` | `{item['actor']}` | `{item['relation']}` | "
                    f"`{item['outcome']}` | {policy} |"
                )
        else:
            lines.extend(["", "No observations supplied."])
    return "\n".join(lines) + "\n"


def write_report(path, content):
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Assess offline synthetic API authorization evidence.")
    parser.add_argument("--evidence", required=True, type=Path, help="synthetic evidence JSON")
    parser.add_argument("--policy", required=True, type=Path, help="permission matrix JSON")
    parser.add_argument("--out-dir", required=True, type=Path, help="directory for both reports")
    args = parser.parse_args(argv)

    try:
        report = assess(load_json(args.evidence), load_json(args.policy))
        output = {
            args.out_dir / "report.json": json.dumps(report, indent=2) + "\n",
            args.out_dir / "report.md": markdown(report),
        }
        input_paths = {args.evidence.resolve(), args.policy.resolve()}
        if input_paths.intersection(path.resolve() for path in output):
            raise InputError("a report path overlaps an input file")
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for path, content in output.items():
            write_report(path, content)
    except (InputError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"Assessed {len(report['cases'])} synthetic cases.")
    for name, count in report["summary"].items():
        print(f"  {name}: {count}")
    for path in output:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
