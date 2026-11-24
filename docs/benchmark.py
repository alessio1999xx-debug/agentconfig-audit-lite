#!/usr/bin/env python3
"""Wall-clock benchmark for agentconfig-audit-lite (fresh python3 process per run).

Usage: python3 docs/benchmark.py [RUNS]
Builds three throwaway fixtures under a temp dir, then times
`python3 agentconfig_audit_lite.py <dir>` RUNS times each (default 20).
Fake tokens are generated at runtime; nothing is written outside the temp dir.
"""
import json, os, platform, shutil, statistics, subprocess, sys, sysconfig, tempfile, time

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 20
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(HERE, "agentconfig_audit_lite.py")

def add_agent_files(root):
    os.makedirs(os.path.join(root, ".claude"), exist_ok=True)
    os.makedirs(os.path.join(root, "migrations"), exist_ok=True)
    open(os.path.join(root, ".env"), "w").write("DATABASE_URL=postgres://localhost/app\n")
    open(os.path.join(root, "CLAUDE.md"), "w").write("# Project rules\n")
    json.dump({"permissions": {"allow": ["Bash(npm test)"]}}, open(os.path.join(root, ".claude", "settings.json"), "w"))
    fake = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9"
    json.dump({"mcpServers": {"github": {"command": "npx", "args": ["@modelcontextprotocol/server-github"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": fake}}}}, open(os.path.join(root, ".mcp.json"), "w"))

def count_files(root):
    return sum(len(f) for _, _, f in os.walk(root))

def bench(path):
    times = []
    for _ in range(RUNS):
        t = time.perf_counter()
        r = subprocess.run([sys.executable, TOOL, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        times.append((time.perf_counter() - t) * 1000)
    return r.returncode, times

def main():
    tmp = tempfile.mkdtemp(prefix="acal-bench-")
    try:
        small = os.path.join(tmp, "small"); os.makedirs(small); add_agent_files(small)
        medium = os.path.join(tmp, "medium")
        shutil.copytree(sysconfig.get_paths()["stdlib"], medium, ignore=shutil.ignore_patterns("__pycache__", "site-packages", "dist-packages"))
        add_agent_files(medium)
        large = os.path.join(tmp, "large"); shutil.copytree(medium, large)
        nm = os.path.join(large, "node_modules")
        for i in range(200):
            d = os.path.join(nm, "pkg%03d" % i); os.makedirs(d)
            for j in range(100):
                open(os.path.join(d, "f%03d.js" % j), "w").write("module.exports = %d;\n" % j)
        print("machine: %s %s, %d CPUs, Python %s; %d fresh-process runs per case" % (
            platform.system(), platform.release(), os.cpu_count(), platform.python_version(), RUNS))
        print("| Project scanned | Files | Median | Min | Max | Exit |")
        print("| --- | ---: | ---: | ---: | ---: | ---: |")
        for name, path in [("small: demo project (4 agent/config files)", small),
                           ("medium: copy of the Python stdlib + agent files", medium),
                           ("large: medium + node_modules with 20,000 files", large)]:
            code, t = bench(path)
            print("| %s | %d | %.1f ms | %.1f ms | %.1f ms | %d |" % (
                name, count_files(path), statistics.median(t), min(t), max(t), code))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
