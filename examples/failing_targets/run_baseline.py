from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "targets.json"


def main() -> int:
    targets = json.loads(MANIFEST.read_text(encoding="utf-8"))
    unexpected = 0

    for item in targets:
        target_id = item["id"]
        target_dir = ROOT / item["path"]
        command = item["command"]

        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            check=False,
        )

        status = "FAILS (expected)" if proc.returncode != 0 else "PASS (unexpected)"
        print(f"[{target_id}] {status} exit={proc.returncode}")

        if proc.returncode == 0:
            unexpected += 1
            print("  expected_failure:", item["expected_failure"])

    print(f"\nChecked {len(targets)} targets")
    if unexpected:
        print(f"Unexpected passing targets: {unexpected}")
        return 1

    print("All targets are failing as expected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
