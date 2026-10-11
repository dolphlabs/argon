#!/usr/bin/env python3
import math
import re
import sys

ITERATIONS = 20
OPS = ("R", "H", "V")


def percentile(values, p):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]


def read_run(path):
    data = {"samples": {op: [] for op in OPS}, "batches": {}, "raw": "", "path": path}
    with open(path, encoding="utf-8") as source:
        for line in source:
            fields = line.split()
            if not fields:
                continue
            if fields[0] == "RAW":
                data["raw"] = fields[1]
            elif fields[0] == "B":
                data["batches"][fields[1]] = int(fields[2])
            elif fields[0] in OPS:
                data["samples"][fields[0]].append(int(fields[1]))
    return data


def rss_kib(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    mac = re.search(r"(\d+)\s+maximum resident set size", text, re.I)
    if mac:
        return int(mac.group(1)) / 1024
    linux = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
    if linux:
        return float(linux.group(1))
    return 0.0


def main(args):
    runs = {}
    for arg in args:
        name, path = arg.split("=", 1)
        lang = "slang" if name.startswith("slang") else "Go"
        key = (lang, name)
        runs[key] = read_run(path)

    print("Operation | slang p50/p99 ms | Go p50/p99 ms | median batch ops/s slang/Go")
    print("---|---:|---:|---:")
    for op in OPS:
        all_samples = {"slang": [], "Go": []}
        throughput = {"slang": [], "Go": []}
        for (lang, name), data in runs.items():
            all_samples[lang].extend(data["samples"][op])
            batch = data["batches"].get(op, 0)
            if batch:
                throughput[lang].append(ITERATIONS * 1e9 / batch)
        def med(xs):
            return percentile(xs, 0.5)

        slang50 = med(all_samples["slang"]) / 1e6
        slang99 = percentile(all_samples["slang"], 0.99) / 1e6
        go50 = med(all_samples["Go"]) / 1e6
        go99 = percentile(all_samples["Go"], 0.99) / 1e6
        slang_rate = med(throughput["slang"])
        go_rate = med(throughput["Go"])
        print(f"{op} | {slang50:.2f}/{slang99:.2f} | "
              f"{go50:.2f}/{go99:.2f} | {slang_rate:.1f}/{go_rate:.1f}")

    slang_rss = []
    go_rss = []
    for (lang, _name), data in runs.items():
        measured = rss_kib(data["path"] + ".time")
        (slang_rss if lang == "slang" else go_rss).append(measured)
    print(f"Peak RSS across benchmark processes: slang {max(slang_rss):.0f} KiB, "
          f"Go {max(go_rss):.0f} KiB")
    print(f"Samples per operation: {ITERATIONS * len(args) // 2} per language")


if __name__ == "__main__":
    main(sys.argv[1:])
