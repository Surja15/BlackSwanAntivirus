#!/usr/bin/env python3
"""
Black Swan AV — latency and resource benchmark harness.
Measures: file-write -> quarantine latency, and CPU/memory of the RTM
process (and its forked engine children) under single-file and burst load.

Requires: pip install psutil
Run as: python3 bench.py --rtm-path ./rtm --watch-dir ~/testdir --corpus-dir ~/samples
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from queue import Queue, Empty

import psutil

# --- log reader thread -------------------------------------------------

def reader_thread(proc, out_queue):
    """Read RTM stdout line by line, timestamp each line the instant it arrives."""
    for raw_line in iter(proc.stdout.readline, b""):
        ts = time.time()
        line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
        out_queue.put((ts, line))

# --- resource sampler thread --------------------------------------------

def resource_sampler(rtm_pid, stop_event, samples, interval=0.1):
    """Poll CPU% and RSS memory of the RTM process and any 'engine' children."""
    try:
        rtm_proc = psutil.Process(rtm_pid)
    except psutil.NoSuchProcess:
        return
    rtm_proc.cpu_percent(None)  # prime the internal counter
    while not stop_event.is_set():
        ts = time.time()
        total_cpu = 0.0
        total_rss = 0
        n_engines = 0
        try:
            total_cpu += rtm_proc.cpu_percent(None)
            total_rss += rtm_proc.memory_info().rss
            for child in rtm_proc.children(recursive=True):
                try:
                    total_cpu += child.cpu_percent(None)
                    total_rss += child.memory_info().rss
                    if "engine" in child.name():
                        n_engines += 1
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        except psutil.NoSuchProcess:
            break
        samples.append((ts, total_cpu, total_rss, n_engines))
        time.sleep(interval)

# --- main benchmark ------------------------------------------------------

def drain_queue_matching(out_queue, filename, timeout=10.0):
    """Wait up to `timeout` s for a log line mentioning `filename`; return ts or None."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ts, line = out_queue.get(timeout=0.2)
        except Empty:
            continue
        # adjust this pattern to whatever your RTM/engine actually prints —
        # e.g. "[+] Event detected: <path>" or "[+] Quarantined: <path>"
        if filename in line and ("Quarantined" in line or "Event detected" in line):
            return ts, line
    return None, None


def run_single_file_test(watch_dir, corpus_files, out_queue, log_rows):
    print(f"\n=== Single-file latency test ({len(corpus_files)} files) ===")
    for src in corpus_files:
        dst = watch_dir / src.name
        t0 = time.time()
        shutil.copy2(src, dst)
        ts_detected, line = drain_queue_matching(out_queue, src.name)
        if ts_detected:
            latency = ts_detected - t0
            print(f"{src.name:40s}  latency={latency*1000:.1f} ms")
            log_rows.append(["single", src.name, t0, ts_detected, latency])
        else:
            print(f"{src.name:40s}  NO DETECTION WITHIN TIMEOUT")
            log_rows.append(["single", src.name, t0, None, None])
        time.sleep(0.5)  # let things settle between files


def run_burst_test(watch_dir, corpus_files, burst_size, out_queue, log_rows):
    print(f"\n=== Burst test: {burst_size} files dropped simultaneously ===")
    batch = corpus_files[:burst_size]
    t0 = time.time()
    for src in batch:
        shutil.copy2(src, watch_dir / src.name)
    remaining = {f.name for f in batch}
    deadline = time.time() + 30.0
    while remaining and time.time() < deadline:
        try:
            ts, line = out_queue.get(timeout=0.2)
        except Empty:
            continue
        for name in list(remaining):
            if name in line and ("Quarantined" in line or "Event detected" in line):
                latency = ts - t0
                print(f"  {name:40s}  latency={latency*1000:.1f} ms  (burst={burst_size})")
                log_rows.append([f"burst{burst_size}", name, t0, ts, latency])
                remaining.discard(name)
    for name in remaining:
        print(f"  {name:40s}  NO DETECTION WITHIN TIMEOUT (burst={burst_size})")
        log_rows.append([f"burst{burst_size}", name, t0, None, None])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rtm-path", required=True, help="path to compiled rtm binary")
    ap.add_argument("--watch-dir", required=True, help="directory RTM will monitor")
    ap.add_argument("--corpus-dir", required=True, help="directory of test files to copy in")
    ap.add_argument("--burst-sizes", type=int, nargs="+", default=[1, 5, 10, 20])
    ap.add_argument("--sample-interval", type=float, default=0.1)
    ap.add_argument("--out-csv", default="bench_results.csv")
    ap.add_argument("--resource-csv", default="resource_usage.csv")
    args = ap.parse_args()

    watch_dir = Path(args.watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)
    corpus_files = sorted(Path(args.corpus_dir).glob("*"))
    if not corpus_files:
        raise SystemExit("No files found in corpus dir.")

    # start RTM
    proc = subprocess.Popen(
        [args.rtm_path, str(watch_dir)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    out_queue: Queue = Queue()
    threading.Thread(target=reader_thread, args=(proc, out_queue), daemon=True).start()
    time.sleep(1.0)  # let RTM finish initial watch registration

    # start resource sampler
    stop_event = threading.Event()
    resource_samples = []
    sampler = threading.Thread(
        target=resource_sampler,
        args=(proc.pid, stop_event, resource_samples, args.sample_interval),
        daemon=True,
    )
    sampler.start()

    log_rows = [["test_type", "filename", "t_copied", "t_detected", "latency_s"]]

    try:
        run_single_file_test(watch_dir, corpus_files, out_queue, log_rows)
        for b in args.burst_sizes:
            run_burst_test(watch_dir, corpus_files, b, out_queue, log_rows)
    finally:
        stop_event.set()
        sampler.join(timeout=2)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    with open(args.out_csv, "w", newline="") as f:
        csv.writer(f).writerows(log_rows)
    with open(args.resource_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "total_cpu_percent", "total_rss_bytes", "n_engine_children"])
        w.writerows(resource_samples)

    print(f"\nWrote latency results to {args.out_csv}")
    print(f"Wrote resource usage to {args.resource_csv}")


if __name__ == "__main__":
    main()
