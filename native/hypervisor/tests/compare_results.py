#!/usr/bin/env python3
"""
AnXinHypervisor - Benchmark Result Comparator

Compares baseline (no hypervisor) vs active (hypervisor loaded) benchmark
results and computes overhead percentage.

Usage:
    python compare_results.py result_baseline.json result_active.json

Target: < 3% overall system impact on both Intel and AMD platforms.
"""

import json
import sys


def load_results(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare(baseline: dict, active: dict) -> None:
    base_results = {r["name"]: r for r in baseline.get("results", [])}
    act_results = {r["name"]: r for r in active.get("results", [])}

    print("=" * 70)
    print(" AnXinHypervisor Performance Comparison")
    print("=" * 70)
    print(f" Baseline hypervisor: {baseline.get('hypervisor_active', '?')}")
    print(f" Active hypervisor:   {active.get('hypervisor_active', '?')}")
    if active.get("hv_platform"):
        print(f" Platform: {active['hv_platform']}")
    if active.get("hv_vendor"):
        print(f" CPU Vendor: {active['hv_vendor']}")
    print(f" CPUs: {active.get('cpus', '?')}")
    print("-" * 70)
    print(f" {'Benchmark':<30} {'Baseline':>12} {'Active':>12} {'Overhead':>10}")
    print(f" {'':30} {'(ops/s)':>12} {'(ops/s)':>12} {'(%)':>10}")
    print("-" * 70)

    total_overhead = 0.0
    count = 0
    max_overhead = 0.0
    worst_name = ""

    for name in base_results:
        if name not in act_results:
            continue
        b = base_results[name]["ops_per_sec"]
        a = act_results[name]["ops_per_sec"]
        if b == 0:
            continue

        overhead = (b - a) / b * 100.0
        total_overhead += overhead
        count += 1

        if overhead > max_overhead:
            max_overhead = overhead
            worst_name = name

        status = "OK" if overhead < 3.0 else "WARN" if overhead < 5.0 else "FAIL"
        print(f" {name:<30} {b:>12.0f} {a:>12.0f} {overhead:>+9.2f}% {status}")

    print("-" * 70)

    if count > 0:
        avg_overhead = total_overhead / count
        print(f" {'AVERAGE':<30} {'':>12} {'':>12} {avg_overhead:>+9.2f}%")
        print(f" {'WORST (' + worst_name + ')':<30} {'':>12} {'':>12} {max_overhead:>+9.2f}%")
        print()

        if avg_overhead < 3.0 and max_overhead < 5.0:
            print(" RESULT: PASS - Overall impact < 3% target met")
        elif avg_overhead < 5.0:
            print(" RESULT: MARGINAL - Average < 5% but exceeds 3% target")
        else:
            print(" RESULT: FAIL - Performance impact exceeds acceptable threshold")
    else:
        print(" No comparable results found.")

    print("=" * 70)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <baseline.json> <active.json>")
        sys.exit(1)

    baseline = load_results(sys.argv[1])
    active = load_results(sys.argv[2])
    compare(baseline, active)


if __name__ == "__main__":
    main()
