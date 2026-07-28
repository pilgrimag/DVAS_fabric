#!/usr/bin/env python3
from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path


CSV_NAME = "dvas-system-raw.csv"
METADATA_NAME = "dvas-system-metadata.txt"
VALIDATION_NAME = "VALIDATION"

HEADER = [
    "scheme",
    "experiment",
    "profile",
    "run",
    "n",
    "ns",
    "mode",
    "report_size_bytes",
    "sensor_to_en_bytes",
    "fabric_mapping_bytes",
    "en_to_dv_bytes",
    "total_communication_bytes",
    "aggregate_evidence_bytes",
    "onchain_application_bytes",
    "offchain_storage_bytes",
    "offchain_store_ns",
    "offchain_fetch_ns",
    "sign_ns",
    "fabric_add_mapping_ns",
    "fabric_query_phi_ns",
    "sigverify_ns",
    "privacy_ns",
    "aggregate_ns",
    "aggverify_ns",
    "total_e2e_ns",
    "throughput_reports_per_s",
    "accepted_count",
    "correctness",
]

PROFILE_CONFIG = {
    "smoke": {
        "runs": 2,
        "warmups": 1,
        "sizes": (2, 4),
    },
    "full": {
        "runs": 30,
        "warmups": 5,
        "sizes": (50, 100, 200, 400, 600, 800, 1000),
    },
}


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def parse_kv(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"Missing file: {path}")

    values: dict[str, str] = {}

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line:
            continue

        if "=" not in line:
            fail(
                f"{path.name}:{line_number}: expected key=value"
            )

        key, value = line.split("=", 1)

        if key in values:
            fail(
                f"{path.name}:{line_number}: duplicate key {key}"
            )

        values[key] = value

    return values


def parse_int(
    value: str,
    field: str,
    row_number: int,
) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ValidationError(
            f"Row {row_number}: {field} is not an integer"
        ) from exc


def parse_float(
    value: str,
    field: str,
    row_number: int,
) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise ValidationError(
            f"Row {row_number}: {field} is not numeric"
        ) from exc

    if not math.isfinite(result):
        fail(f"Row {row_number}: {field} is not finite")

    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: validate_dvas_system.py "
            "<result-directory> <smoke|full>",
            file=sys.stderr,
        )
        return 2

    root = Path(sys.argv[1]).resolve()
    profile = sys.argv[2].lower()

    if profile not in PROFILE_CONFIG:
        fail(f"Unknown profile: {profile}")

    config = PROFILE_CONFIG[profile]
    csv_path = root / CSV_NAME

    if not csv_path.is_file():
        fail(f"Missing CSV: {csv_path}")

    with csv_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames != HEADER:
            fail("CSV header mismatch")

        rows = list(reader)

    expected_scenarios = {
        (n, mode)
        for n in config["sizes"]
        for mode in ("allfix", "alladm")
    }

    expected_rows = (
        len(expected_scenarios)
        * config["runs"]
    )

    if len(rows) != expected_rows:
        fail(
            f"Expected {expected_rows} rows, found {len(rows)}"
        )

    scenario_runs: dict[
        tuple[int, str],
        set[int],
    ] = defaultdict(set)

    seen: set[tuple[int, str, int]] = set()

    for row_number, row in enumerate(rows, start=2):
        if None in row:
            fail(f"Row {row_number}: extra columns")

        if row["scheme"] != "DVAS":
            fail(f"Row {row_number}: scheme must be DVAS")

        if row["experiment"] != "system_size_sweep":
            fail(
                f"Row {row_number}: invalid experiment"
            )

        if row["profile"] != profile:
            fail(f"Row {row_number}: profile mismatch")

        n = parse_int(row["n"], "n", row_number)
        ns = parse_int(row["ns"], "ns", row_number)
        run = parse_int(row["run"], "run", row_number)
        mode = row["mode"]

        scenario = (n, mode)

        if scenario not in expected_scenarios:
            fail(
                f"Row {row_number}: unexpected scenario "
                f"{scenario}"
            )

        expected_ns = n if mode == "alladm" else 0

        if ns != expected_ns:
            fail(f"Row {row_number}: ns mismatch")

        if run < 1 or run > config["runs"]:
            fail(f"Row {row_number}: invalid run")

        unique = (n, mode, run)

        if unique in seen:
            fail(f"Row {row_number}: duplicate measurement")

        seen.add(unique)
        scenario_runs[scenario].add(run)

        if (
            parse_int(
                row["report_size_bytes"],
                "report_size_bytes",
                row_number,
            ) != 1024
        ):
            fail(f"Row {row_number}: report size mismatch")

        byte_fields = (
            "sensor_to_en_bytes",
            "fabric_mapping_bytes",
            "en_to_dv_bytes",
            "total_communication_bytes",
            "aggregate_evidence_bytes",
            "onchain_application_bytes",
        )

        byte_values = {
            field: parse_int(
                row[field],
                field,
                row_number,
            )
            for field in byte_fields
        }

        if any(value <= 0 for value in byte_values.values()):
            fail(
                f"Row {row_number}: byte metrics must be positive"
            )

        expected_communication = (
            byte_values["sensor_to_en_bytes"]
            + byte_values["fabric_mapping_bytes"]
            + byte_values["en_to_dv_bytes"]
        )

        if (
            byte_values["total_communication_bytes"]
            != expected_communication
        ):
            fail(
                f"Row {row_number}: "
                "total communication mismatch"
            )

        if (
            byte_values["onchain_application_bytes"]
            != byte_values["fabric_mapping_bytes"]
        ):
            fail(
                f"Row {row_number}: on-chain size mismatch"
            )

        for field in (
            "offchain_storage_bytes",
            "offchain_store_ns",
            "offchain_fetch_ns",
        ):
            if row[field] != "":
                fail(
                    f"Row {row_number}: {field} must be blank"
                )

        time_fields = (
            "sign_ns",
            "fabric_add_mapping_ns",
            "fabric_query_phi_ns",
            "sigverify_ns",
            "privacy_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_e2e_ns",
        )

        times = {
            field: parse_int(
                row[field],
                field,
                row_number,
            )
            for field in time_fields
        }

        for field in (
            "sign_ns",
            "fabric_add_mapping_ns",
            "fabric_query_phi_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_e2e_ns",
        ):
            if times[field] <= 0:
                fail(
                    f"Row {row_number}: {field} "
                    "must be positive"
                )

        if mode == "allfix" and times["privacy_ns"] != 0:
            fail(
                f"Row {row_number}: "
                "allfix privacy_ns must be zero"
            )

        if mode == "alladm" and times["privacy_ns"] <= 0:
            fail(
                f"Row {row_number}: "
                "alladm privacy_ns must be positive"
            )

        expected_e2e = (
            times["sign_ns"]
            + times["fabric_add_mapping_ns"]
            + times["fabric_query_phi_ns"]
            + times["sigverify_ns"]
            + times["privacy_ns"]
            + times["aggregate_ns"]
            + times["aggverify_ns"]
        )

        if times["total_e2e_ns"] != expected_e2e:
            fail(
                f"Row {row_number}: total_e2e_ns mismatch"
            )

        throughput = parse_float(
            row["throughput_reports_per_s"],
            "throughput_reports_per_s",
            row_number,
        )

        expected_throughput = (
            n * 1_000_000_000.0
            / times["total_e2e_ns"]
        )

        relative_error = abs(
            throughput - expected_throughput
        ) / expected_throughput

        if relative_error > 1e-9:
            fail(
                f"Row {row_number}: throughput mismatch"
            )

        if (
            parse_int(
                row["accepted_count"],
                "accepted_count",
                row_number,
            ) != n
        ):
            fail(
                f"Row {row_number}: accepted_count mismatch"
            )

        if row["correctness"] != "true":
            fail(f"Row {row_number}: correctness is not true")

    expected_runs = set(range(1, config["runs"] + 1))

    if set(scenario_runs) != expected_scenarios:
        fail("Scenario set mismatch")

    for scenario in expected_scenarios:
        if scenario_runs[scenario] != expected_runs:
            fail(
                f"Scenario {scenario}: run set mismatch"
            )

    metadata = parse_kv(root / METADATA_NAME)
    validation = parse_kv(root / VALIDATION_NAME)

    required_metadata = {
        "scheme": "DVAS",
        "benchmark": "real-fabric-system",
        "profile": profile,
        "warmup_runs": str(config["warmups"]),
        "measurement_runs": str(config["runs"]),
        "report_size_bytes": "1024",
        "scenario_count": str(len(expected_scenarios)),
        "rows": str(expected_rows),
        "fabric_included": "true",
        "ipfs_included": "false",
        "fig12_offchain_storage": "not_applicable",
    }

    for key, expected in required_metadata.items():
        if metadata.get(key) != expected:
            fail(
                f"Metadata {key}: expected {expected!r}, "
                f"found {metadata.get(key)!r}"
            )

    required_validation = {
        "validation": "PASS",
        "scheme": "DVAS",
        "profile": profile,
        "rows": str(expected_rows),
        "scenarios": str(len(expected_scenarios)),
        "all_correctness": "true",
        "communication_sum_check": "PASS",
        "total_e2e_sum_check": "PASS",
        "fabric_included": "true",
        "ipfs_included": "false",
        "offchain_storage": "not_applicable",
    }

    for key, expected in required_validation.items():
        if validation.get(key) != expected:
            fail(
                f"VALIDATION {key}: expected {expected!r}, "
                f"found {validation.get(key)!r}"
            )

    print("DVAS system CSV validation: PASS")
    print(f"profile={profile}")
    print(f"rows={expected_rows}")
    print(f"scenarios={len(expected_scenarios)}")
    print(f"measurement_runs={config['runs']}")
    print("report_size_bytes=1024")
    print("fabric_included=true")
    print("ipfs_included=false")
    print("offchain_storage=not_applicable")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(
            f"DVAS system CSV validation: FAIL: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
