#!/usr/bin/env python3
"""Create one reviewable proposal per stable Codex version, without changing support."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

from check_compatibility import stable_version, supported_version


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def write_body(command, title, body, *extra):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md") as file:
        file.write(body)
        file.flush()
        return run("gh", command, "create", "--title", title, "--body-file", file.name, *extra)


def validate_evidence(evidence, version):
    if (evidence.get("candidate_codex_version") != version
            or evidence.get("supported_codex_version") != supported_version()
            or evidence.get("status") not in {"needs-review", "offline-checks-passed"}
            or evidence.get("live_relay_validated") is not False
            or not isinstance(evidence.get("schema_changes"), list)
            or len(evidence["schema_changes"]) > 10000
            or any(not isinstance(item, str) or len(item) > 1024 for item in evidence["schema_changes"])):
        raise ValueError("invalid offline compatibility evidence")


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    run_url = f"https://github.com/{repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    if "--failure" in sys.argv:
        title = "Codex compatibility check needs attention"
        existing = json.loads(run("gh", "issue", "list", "--repo", repository, "--state", "open",
                                  "--search", f'"{title}" in:title', "--json", "title"))
        if not any(issue["title"] == title for issue in existing):
            write_body("issue", title, f"The scheduled offline check failed. Review [the workflow run]({run_url}).\n\n"
                       "The supported Codex version remains unchanged. Registry or runner failures do not prove incompatibility.\n",
                       "--repo", repository)
        return
    version = stable_version(os.environ["CANDIDATE"])
    report = pathlib.Path(f"compatibility/candidates/{version}.json")
    if report.stat().st_size > 1024 * 1024:
        raise ValueError("compatibility evidence too large")
    evidence = json.loads(report.read_text())
    validate_evidence(evidence, version)
    branch = f"automation/codex-compatibility-{version}"
    existing = json.loads(run("gh", "pr", "list", "--repo", repository, "--head", branch,
                              "--state", "all", "--json", "number"))
    if existing:
        print("A proposal already exists for this version; leaving human review intact.")
        return
    if run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"):
        # Recover a push that succeeded before PR creation failed, without force-pushing.
        run("git", "fetch", "--depth=1", "origin", branch)
        previous = json.loads(run("git", "show", f"FETCH_HEAD:{report}"))
        if previous != evidence:
            raise ValueError("orphan proposal branch has different evidence; inspect it before retrying")
        revision = run("git", "rev-parse", "--short", "FETCH_HEAD")
    else:
        run("git", "switch", "-c", branch)
        run("git", "config", "user.name", "github-actions[bot]")
        run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        run("git", "add", str(report))
        run("git", "commit", "-m", f"chore: record Codex {version} compatibility evidence")
        run("git", "push", "origin", branch)
        revision = run("git", "rev-parse", "--short", "HEAD")
    body = (f"Codex {version} is available. Offline result: `{evidence['status']}`. "
            f"[Check evidence]({run_url}). This proposal records schema/CLI evidence; the compatibility pin stays unchanged.\n\n"
            "After live validation, make a separate implementation change to the compatibility pin, tests, README and changelog, "
            "then rerun CI and personal testing. Do not treat a matching schema as proof of relay compatibility.\n\n"
            "## Manual test\n\n- [ ] I personally tested this feature and approve merging.\n\n"
            f"Test plan: On a dedicated authenticated Mac and paired test host running Codex {version}, "
            "test enrollment/session refresh, relay initialization, then the stock TUI with a remote task and cancellation "
            "using a candidate build. Confirm reconnect and cleanup.\n\n"
            f"Revision to test: {revision} (evidence only; candidate runtime revision must be recorded separately).\n")
    write_body("pr", f"Review compatibility with Codex {version}", body, "--repo", repository,
               "--head", branch, "--base", os.environ["DEFAULT_BRANCH"], "--draft")


if __name__ == "__main__":
    main()
