"""A small honest stopwatch for the Task-5 benchmarks.

WHY this shape (for viva):
  * time.perf_counter (monotonic, highest resolution) -- never time.time,
    which can jump if the OS adjusts the clock.
  * One warm-up run first: it faults pages in, warms the CPU cache and lets
    Python's allocator settle, so the timed runs measure steady state.
  * Keep ALL samples and report median/min/stdev, not just the mean: the
    median resists one-off OS hiccups, the min shows the noise-free floor,
    and stdev says how stable the box was. A mean alone hides outliers.

Repeat budget (comment required by the brief): our AES needs ~0.1 ms per
block, so repeats are picked per message size to land each cell near one
second of measuring: 64 B -> 200 reps, 1 KB -> 30, 16 KB -> 5, 64 KB -> 3,
256 KB -> 2. Twelve encrypt/decrypt ops x five sizes then costs roughly
half a minute plus warm-ups -- well under the two-minute ceiling.
"""

import platform
import statistics
import time


def machine_info():
    """Machine/OS/CPU/Python -- benchmark numbers are meaningless without."""
    cpu = platform.processor()
    try:  # Linux: prettier CPU name from /proc/cpuinfo
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass  # keep platform.processor() fallback on other OSes
    return {"machine": platform.machine(),
            "os": "%s %s" % (platform.system(), platform.release()),
            "cpu": cpu,
            "python": platform.python_version()}


def repeats_for(size_bytes):
    """How many timed repeats for a message of this size (see table above)."""
    if size_bytes <= 64:
        return 200
    if size_bytes <= 1024:
        return 30
    if size_bytes <= 16 * 1024:
        return 5
    if size_bytes <= 64 * 1024:
        return 3
    return 2


def measure(fn, reps):
    """Time fn() `reps` times (after 1 warm-up). Returns milliseconds dict.

    Keys: samples (every run, in ms), median_ms, min_ms, stdev_ms.
    fn must take no arguments -- wrap setup with a lambda at the call site
    so only the measured work is inside the timed region.
    """
    fn()  # warm-up, discarded
    samples = []
    for _ in range(reps):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
    return {"samples": samples,
            "median_ms": statistics.median(samples),
            "min_ms": min(samples),
            "stdev_ms": stdev}
