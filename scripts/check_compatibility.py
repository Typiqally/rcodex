#!/usr/bin/env python3
"""Offline compatibility evidence only; never approves relay support or changes its pin."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")


def stable_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("expected a stable semantic version")
    return value


def supported_version():
    source = (ROOT / "src" / "compatibility.rs").read_text()
    match = re.search(r'VALIDATED_CODEX_VERSION: &str = "([^"]+)"', source)
    if not match:
        raise ValueError("could not find the validated Codex baseline")
    return stable_version(match.group(1))


def normalized(value):
    if isinstance(value, dict):
        mappings = {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
        subschemas = {"items", "prefixItems", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
                      "contains", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "propertyNames"}
        result = {}
        for key, item in value.items():
            if key in {"description", "title", "$comment"}:
                continue
            if key in mappings and isinstance(item, dict):
                result[key] = {name: normalized(schema) for name, schema in item.items()}
            elif key in subschemas:
                result[key] = normalized(item)
            else:
                # Enum/default/const values and unknown keywords may contain literal wire data.
                result[key] = item
        return result
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def schema_changes(baseline, candidate):
    def schemas(directory):
        result = {str(path.relative_to(directory)): normalized(json.loads(path.read_text()))
                  for path in directory.rglob("*.json")}
        if not result:
            raise ValueError("empty App Server schema bundle")
        return result
    before, after = schemas(baseline), schemas(candidate)
    changes = [f"removed: {name}" for name in before.keys() - after.keys()]
    changes += [f"added: {name}" for name in after.keys() - before.keys()]
    changes += [f"changed: {name}" for name in before.keys() & after.keys() if before[name] != after[name]]
    return sorted(changes)


def release_manifest(version, codex_version, directory):
    stable_version(version)
    stable_version(codex_version)
    assets = []
    for target in TARGETS:
        name = f"rcodex-{version}-{target}"
        path = directory / name
        if path.is_file():
            data = path.read_bytes()
            if not data or len(data) > 128 * 1024 * 1024:
                raise ValueError("binary size outside updater limits")
            assets.append({"name": name, "target": target, "size": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()})
    if not assets:
        raise ValueError("no matching release binaries")
    return {"schema_version": 1, "version": version, "codex_versions": [codex_version], "assets": assets}


def output(values):
    print(json.dumps(values, indent=2))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as file:
            for key, value in values.items():
                file.write(f"{key}={value}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("detect")
    compare = commands.add_parser("compare")
    compare.add_argument("--version", required=True)
    compare.add_argument("--baseline", type=pathlib.Path, required=True)
    compare.add_argument("--candidate", type=pathlib.Path, required=True)
    compare.add_argument("--baseline-help", type=pathlib.Path, required=True)
    compare.add_argument("--candidate-help", type=pathlib.Path, required=True)
    compare.add_argument("--out", type=pathlib.Path, required=True)
    release = commands.add_parser("manifest")
    release.add_argument("--version", required=True)
    release.add_argument("--directory", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.command == "detect":
        with urllib.request.urlopen("https://registry.npmjs.org/@openai%2Fcodex/latest", timeout=20) as response:
            data = response.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError("registry response too large")
        latest = stable_version(json.loads(data)["version"])
        output({"latest": latest, "supported": supported_version()})
    elif args.command == "compare":
        version = stable_version(args.version)
        for path in (args.baseline_help, args.candidate_help):
            for option in ("--remote ", "--remote-auth-token-env "):
                if option not in path.read_text():
                    raise ValueError(f"required CLI option missing: {option.strip()}")
        changes = schema_changes(args.baseline, args.candidate)
        report = {"supported_codex_version": supported_version(), "candidate_codex_version": version,
                  "status": "needs-review" if changes else "offline-checks-passed",
                  "schema_changes": changes, "live_relay_validated": False}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    else:
        manifest = release_manifest(args.version, supported_version(), args.directory)
        (args.directory / "rcodex-update.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
