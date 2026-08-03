#!/usr/bin/env python3
"""Generate a perf baseline JSON artifact for dcg.

This script measures process-per-invocation latency for representative commands
and records p50/p95/p99/mean/throughput with basic build metadata.

Usage:
  ./scripts/perf_baseline.py --bin ./target/release/dcg --output perf/baselines/latest.json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def run_one(bin_path: str, command: str, env: Optional[Dict[str, str]] = None) -> float:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    start = time.perf_counter_ns()
    subprocess.run(
        [bin_path],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=env,
    )
    end = time.perf_counter_ns()
    return (end - start) / 1_000_000.0


def measure_max_rss_kb(bin_path: str, command: str, env: Optional[Dict[str, str]] = None) -> Optional[int]:
    """Measure max RSS in KB using /usr/bin/time -v."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    # Merge custom env with current environment if provided
    run_env = None
    if env is not None:
        run_env = os.environ.copy()
        run_env.update(env)
    try:
        result = subprocess.run(
            ["/usr/bin/time", "-v", bin_path],
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            env=run_env,
        )
        # Parse "Maximum resident set size (kbytes): NNNN" from stderr
        for line in result.stderr.decode(errors="replace").splitlines():
            if "Maximum resident set size" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    return int(parts[1].strip())
        return None
    except Exception:
        return None


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(round((pct / 100.0) * (len(sorted_values) - 1)))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return sorted_values[idx]


def run_case(
    bin_path: str,
    command: str,
    env: Optional[Dict[str, str]],
    warmup: int,
    runs: int,
    measure_rss: bool = True,
) -> Dict[str, Any]:
    for _ in range(warmup):
        run_one(bin_path, command, env)

    timings = [run_one(bin_path, command, env) for _ in range(runs)]
    timings_sorted = sorted(timings)

    mean_ms = sum(timings_sorted) / len(timings_sorted)
    throughput = 1000.0 / mean_ms if mean_ms > 0 else 0.0

    # Measure max RSS (single measurement after warmup)
    max_rss_kb = None
    if measure_rss:
        max_rss_kb = measure_max_rss_kb(bin_path, command, env)

    return {
        "p50_ms": statistics.median(timings_sorted),
        "p95_ms": percentile(timings_sorted, 95),
        "p99_ms": percentile(timings_sorted, 99),
        "mean_ms": mean_ms,
        "throughput_per_s": throughput,
        "sample_count": len(timings_sorted),
        "max_rss_kb": max_rss_kb,
    }


def capture_version_output(bin_path: str) -> str:
    try:
        result = subprocess.run(
            [bin_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()
        return output
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


def capture_rustc_version() -> Tuple[str, Optional[str]]:
    try:
        result = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout.strip()
        host = None
        for line in output.splitlines():
            if line.startswith("host:"):
                host = line.split(":", 1)[1].strip()
        return output, host
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}", None


def capture_git_sha() -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        sha = result.stdout.strip()
        return sha if sha else None
    except Exception:
        return None


def capture_trace(bin_path: str, command: str) -> Optional[Dict[str, Any]]:
    """Run command with trace logging and capture the output."""
    env = os.environ.copy()
    env["DCG_TRACE"] = "1"
    
    try:
        result = subprocess.run(
            [bin_path, "explain", command, "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
            env=env
        )
        if result.returncode != 0:
            return None
            
        try:
            payload = json.loads(result.stdout)
            return payload.get("trace")
        except json.JSONDecodeError:
            return None
            
    except Exception:
        return None


def build_cases() -> List[Dict[str, Any]]:
    return [
        {
            "id": "quick_reject",
            "description": "No pack keywords (fast allow)",
            "command": "ls -la",
            "env": {},
        },
        {
            "id": "safe_keyword",
            "description": "Keyword present, safe path",
            "command": "git status",
            "env": {},
        },
        {
            "id": "destructive_keyword",
            "description": "Keyword present, destructive match",
            "command": "git reset --hard",
            "env": {},
        },
        {
            "id": "heredoc_inline",
            "description": "Inline script trigger",
            "command": "python -c \"import os; os.system('rm -rf /')\"",
            "env": {},
        },
        {
            "id": "bypass",
            "description": "Bypass hook via DCG_BYPASS",
            "command": "git reset --hard",
            "env": {"DCG_BYPASS": "1"},
        },
        # Cold-process classes added after #245/#248: the historical case set
        # above never exercised the full-evaluation path that a keyword hit
        # without an early semantic decision takes, so per-invocation pattern
        # compilation cost was invisible to this tool.
        {
            "id": "full_eval_redirect",
            "description": "Redirect keyword forces full evaluation (#245 case C)",
            "command": "echo hi 2>/dev/null",
            "env": {},
        },
        {
            "id": "full_eval_copy",
            "description": "cp keyword forces full evaluation without a match",
            "command": "cp report.txt backup.txt",
            "env": {},
        },
        {
            "id": "posix_test_probe",
            "description": "POSIX test builtin probe (#246 measured 491ms on 0.7.8)",
            "command": '[ -f x ]',
            "env": {},
        },
        {
            "id": "xargs_fixed_template",
            "description": "Pipeline consumer with fixed -I template (recursive evaluation)",
            "command": "cat repos.txt | xargs -P12 -I{} sh -c 'cd {} && git status'",
            "env": {},
        },
        {
            "id": "multi_construct_245",
            "description": "The #245 deterministic-abort reproducer shape",
            "command": (
                'd=/tmp/gt2\nmkdir -p "$d"; cd "$d"\n'
                "git init -q . 2>/dev/null; git config user.email t@t.t\n"
                "echo hi > a.txt; git add a.txt; git commit -qm init 2>&1 | head -2\n"
                "am guard install gt2 \"$d\" 2>&1 | head -20\n"
                'ls -la .git/hooks/ | grep -vE "sample"'
            ),
            "env": {},
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate dcg perf baseline JSON")
    parser.add_argument("--bin", default="./target/release/dcg", help="Path to dcg binary")
    parser.add_argument("--output", help="Write JSON output to this file")
    parser.add_argument("--warmup", type=int, default=30, help="Warmup iterations per case")
    parser.add_argument("--runs", type=int, default=300, help="Measured iterations per case")
    parser.add_argument("--skip-trace", action="store_true", help="Skip explain trace capture")
    parser.add_argument(
        "--assert-budget-ms",
        type=int,
        default=0,
        help=(
            "Absolute latency gate: fail (exit 3) unless every case's cold "
            "p95 fits within this budget after applying --assert-margin-pct. "
            "This is the #245 regression guard — the baseline comparison's "
            "relative ratchet cannot enforce the product's fixed hook "
            "deadline, so this must be the shipped default budget in ms."
        ),
    )
    parser.add_argument(
        "--assert-margin-pct",
        type=int,
        default=50,
        help=(
            "Percentage of --assert-budget-ms that cold p95 may consume "
            "(default 50: headroom for loaded hosts and slower hardware)"
        ),
    )
    args = parser.parse_args()

    if not os.path.isfile(args.bin):
        print(f"error: binary not found: {args.bin}", file=sys.stderr)
        return 1

    version_output = capture_version_output(args.bin)
    rustc_output, rustc_host = capture_rustc_version()
    git_sha = capture_git_sha()

    base_env = dict(os.environ)
    isolated_home = None
    if args.assert_budget_ms > 0:
        # Gate mode measures the SHIPPED defaults: strip every ambient DCG_*
        # override and point HOME/XDG at an empty directory so no user or
        # system config can raise the budget or change the enabled packs.
        import tempfile

        isolated_home = tempfile.mkdtemp(prefix="dcg-latency-gate-home-")
        base_env = {
            k: v for k, v in base_env.items() if not k.startswith("DCG_")
        }
        base_env["HOME"] = isolated_home
        base_env["USERPROFILE"] = isolated_home
        base_env["XDG_CONFIG_HOME"] = os.path.join(isolated_home, ".config")
        base_env["DCG_SELF_HEAL_HOOK"] = "0"

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for case in build_cases():
        env = base_env.copy()
        env.update(case.get("env", {}))
        try:
            metrics = run_case(args.bin, case["command"], env, args.warmup, args.runs)
            trace = None
            if not args.skip_trace:
                trace = capture_trace(args.bin, case["command"])
            results.append(
                {
                    "id": case["id"],
                    "description": case["description"],
                    "command": case["command"],
                    "env": case.get("env", {}),
                    "metrics": metrics,
                    "trace": trace,
                }
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{case['id']}: {exc}")

    payload = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": {
            "path": args.bin,
            "version_output": version_output,
            "git_sha": git_sha,
        },
        "rustc": {
            "version_output": rustc_output,
            "host": rustc_host,
        },
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
        },
        "method": {
            "mode": "process",
            "warmup": args.warmup,
            "runs": args.runs,
            "timer": "perf_counter_ns",
            "rss_method": "/usr/bin/time -v",
            "notes": "Process-per-invocation timing. max_rss_kb measured via /usr/bin/time -v.",
        },
        "cases": results,
        "errors": errors,
    }

    output_json = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output_json)
            handle.write("\n")
    else:
        print(output_json)

    if errors:
        print(f"error: {len(errors)} case(s) failed to run: {errors}", file=sys.stderr)
        return 1

    if args.assert_budget_ms > 0:
        # Self-validate the isolation before trusting any measurement. A
        # leaked config with a SMALL budget would make dcg abort early and
        # look FASTER, so a broken product could sail through this gate. Read
        # the budget dcg actually resolved under the same isolated env.
        try:
            probe = subprocess.run(
                [args.bin, "config", "--format", "json"],
                capture_output=True,
                text=True,
                check=False,
                env=base_env,
            )
            effective = json.loads(probe.stdout or "{}").get("general", {})
            source = effective.get("hook_timeout_source")
            resolved = effective.get("hook_timeout_ms")
        except Exception as exc:  # noqa: BLE001
            print(f"error: could not verify effective hook budget: {exc}", file=sys.stderr)
            return 3
        if source == "configured":
            print(
                "LATENCY GATE ABORTED: hook_timeout_ms is explicitly configured "
                f"({resolved}ms) despite env/HOME isolation — an override reached "
                "this run, so the measurements would validate the override "
                "instead of the shipped default (#245).",
                file=sys.stderr,
            )
            return 3
        if source == "default" and resolved != args.assert_budget_ms:
            print(
                f"LATENCY GATE ABORTED: dcg resolved a {resolved}ms default budget "
                f"but the gate was told to assert {args.assert_budget_ms}ms. The "
                "caller and src/perf.rs have drifted apart.",
                file=sys.stderr,
            )
            return 3
        print(
            json.dumps(
                {
                    "event": "latency_gate_env",
                    "effective_budget_ms": resolved,
                    "budget_source": source,
                    "isolated_home": isolated_home,
                }
            ),
            file=sys.stderr,
        )

        # The absolute gate. Every case must reach a decision cold within the
        # margin — including 'bypass' (an env escape hatch must never be the
        # slow path). Exceeding the margin means real machines are eating into
        # the fail-closed deadline and users are one loaded host away from
        # every command turning into a review prompt (#245).
        limit_ms = args.assert_budget_ms * args.assert_margin_pct / 100.0
        violations = []
        for case in results:
            p95 = case["metrics"]["p95_ms"]
            status = "ok" if p95 <= limit_ms else "OVER"
            print(
                json.dumps(
                    {
                        "event": "latency_gate_case",
                        "case": case["id"],
                        "p50_ms": round(case["metrics"]["p50_ms"], 1),
                        "p95_ms": round(p95, 1),
                        "limit_ms": limit_ms,
                        "budget_ms": args.assert_budget_ms,
                        "status": status,
                    }
                ),
                file=sys.stderr,
            )
            if p95 > limit_ms:
                violations.append(
                    f"{case['id']}: cold p95 {p95:.1f}ms exceeds "
                    f"{limit_ms:.0f}ms ({args.assert_margin_pct}% of the "
                    f"{args.assert_budget_ms}ms hook budget)"
                )
        if violations:
            print(
                "LATENCY GATE FAILED — per-invocation cost is eating the "
                "fail-closed hook deadline (#245 regression class):",
                file=sys.stderr,
            )
            for violation in violations:
                print(f"  {violation}", file=sys.stderr)
            return 3
        print(
            f"LATENCY GATE PASSED: {len(results)} cases, cold p95 within "
            f"{args.assert_margin_pct}% of the {args.assert_budget_ms}ms budget",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
