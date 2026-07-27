#!/usr/bin/env python3
from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path


CSV_NAME = "dvas-crypto-raw.csv"
METADATA_NAME = "dvas-crypto-metadata.txt"
VALIDATION_NAME = "VALIDATION"

HEADER = [
    "scheme",
    "experiment",
    "profile",
    "run",
    "n",
    "ns",
    "nr",
    "report_size_bytes",
    "sign_ns",
    "kem_encap_ns",
    "aead_encrypt_ns",
    "privacy_ns",
    "sigverify_ns",
    "aggregate_ns",
    "aggverify_ns",
    "total_crypto_ns",
    "kem_decap_ns",
    "aead_decrypt_ns",
    "recovery_ns",
    "accepted_count",
    "correctness",
]

BLANK_FIELDS = {
    "nr",
    "kem_encap_ns",
    "aead_encrypt_ns",
    "kem_decap_ns",
    "aead_decrypt_ns",
    "recovery_ns",
}

TIME_FIELDS = {
    "sign_ns",
    "privacy_ns",
    "sigverify_ns",
    "aggregate_ns",
    "aggverify_ns",
    "total_crypto_ns",
}

PROFILE_CONFIG = {
    "smoke": {
        "warmup_runs": 1,
        "measurement_runs": 2,
        "scenarios": {
            ("size_sweep", 2, 0),
            ("size_sweep", 4, 0),
            ("sensitive_sweep", 4, 1),
            ("sensitive_sweep", 4, 3),
        },
    },
    "full": {
        "warmup_runs": 5,
        "measurement_runs": 30,
        "scenarios": {
            ("size_sweep", 50, 0),
            ("size_sweep", 100, 0),
            ("size_sweep", 200, 0),
            ("size_sweep", 400, 0),
            ("size_sweep", 600, 0),
            ("size_sweep", 800, 0),
            ("size_sweep", 1000, 0),
            ("sensitive_sweep", 200, 10),
            ("sensitive_sweep", 200, 30),
            ("sensitive_sweep", 200, 70),
            ("sensitive_sweep", 200, 120),
            ("sensitive_sweep", 200, 170),
            ("sensitive_sweep", 200, 190),
        },
    },
}


class ValidationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"Missing file: {path}")

    values: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line:
            continue

        if "=" not in line:
            fail(
                f"{path.name}:{line_number}: "
                "expected key=value"
            )

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            fail(
                f"{path.name}:{line_number}: "
                "empty key"
            )

        if key in values:
            fail(
                f"{path.name}:{line_number}: "
                f"duplicate key {key!r}"
            )

        values[key] = value

    return values


def parse_int(
    value: str,
    field: str,
    row_number: int,
) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValidationError(
            f"CSV row {row_number}: "
            f"{field} is not an integer: {value!r}"
        ) from exc

    return parsed


def require_equal(
    actual: str | None,
    expected: str,
    description: str,
) -> None:
    if actual != expected:
        fail(
            f"{description}: expected {expected!r}, "
            f"found {actual!r}"
        )


def validate_metadata(
    metadata: dict[str, str],
    profile: str,
    expected_rows: int,
    expected_scenarios: int,
) -> None:
    config = PROFILE_CONFIG[profile]

    required = {
        "scheme": "DVAS",
        "benchmark": "pure-cryptography",
        "profile": profile,
        "warmup_runs": str(config["warmup_runs"]),
        "measurement_runs": str(
            config["measurement_runs"]
        ),
        "report_size_bytes": "1024",
        "pairing": "JPBC-Type-A",
        "pairing_r_bits": "160",
        "pairing_q_bits": "512",
        "masking_rule": "DVAS_MASK_V1",
        "scenario_count": str(expected_scenarios),
        "rows": str(expected_rows),
        "timing_clock": "System.nanoTime",
        "fig8_recovery": "not_applicable",
        "fabric_included": "false",
        "ipfs_included": "false",
        "setup_included": "false",
        "key_distribution_included": "false",
        "message_construction_included": "false",
        "csv_io_included": "false",
    }

    for key, expected in required.items():
        require_equal(
            metadata.get(key),
            expected,
            f"metadata {key}",
        )


def validate_internal_validation(
    values: dict[str, str],
    profile: str,
    expected_rows: int,
    expected_scenarios: int,
) -> None:
    required = {
        "validation": "PASS",
        "scheme": "DVAS",
        "profile": profile,
        "rows": str(expected_rows),
        "scenarios": str(expected_scenarios),
        "report_size_bytes": "1024",
        "all_correctness": "true",
        "total_crypto_sum_check": "PASS",
        "fabric_included": "false",
        "ipfs_included": "false",
    }

    for key, expected in required.items():
        require_equal(
            values.get(key),
            expected,
            f"VALIDATION {key}",
        )


def validate_csv(
    csv_path: Path,
    profile: str,
) -> tuple[int, int]:
    if not csv_path.is_file():
        fail(f"Missing file: {csv_path}")

    config = PROFILE_CONFIG[profile]
    expected_scenarios = config["scenarios"]
    measurement_runs = config["measurement_runs"]
    expected_rows = (
        len(expected_scenarios) * measurement_runs
    )

    with csv_path.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames != HEADER:
            fail(
                "CSV header mismatch.\n"
                f"Expected: {HEADER}\n"
                f"Found:    {reader.fieldnames}"
            )

        rows = list(reader)

    if len(rows) != expected_rows:
        fail(
            f"CSV row count: expected {expected_rows}, "
            f"found {len(rows)}"
        )

    scenario_runs: dict[
        tuple[str, int, int],
        set[int],
    ] = defaultdict(set)

    seen: set[tuple[str, int, int, int]] = set()

    for row_number, row in enumerate(
        rows,
        start=2,
    ):
        if None in row:
            fail(
                f"CSV row {row_number}: "
                "contains extra columns"
            )

        require_equal(
            row["scheme"],
            "DVAS",
            f"CSV row {row_number} scheme",
        )

        require_equal(
            row["profile"],
            profile,
            f"CSV row {row_number} profile",
        )

        experiment = row["experiment"]

        if experiment not in {
            "size_sweep",
            "sensitive_sweep",
        }:
            fail(
                f"CSV row {row_number}: "
                f"unknown experiment {experiment!r}"
            )

        run = parse_int(
            row["run"],
            "run",
            row_number,
        )
        n = parse_int(
            row["n"],
            "n",
            row_number,
        )
        ns = parse_int(
            row["ns"],
            "ns",
            row_number,
        )
        report_size = parse_int(
            row["report_size_bytes"],
            "report_size_bytes",
            row_number,
        )
        accepted_count = parse_int(
            row["accepted_count"],
            "accepted_count",
            row_number,
        )

        scenario = (experiment, n, ns)

        if scenario not in expected_scenarios:
            fail(
                f"CSV row {row_number}: "
                f"unexpected scenario {scenario}"
            )

        if run < 1 or run > measurement_runs:
            fail(
                f"CSV row {row_number}: "
                f"run {run} outside 1..{measurement_runs}"
            )

        unique_key = (
            experiment,
            n,
            ns,
            run,
        )

        if unique_key in seen:
            fail(
                f"CSV row {row_number}: "
                f"duplicate measurement {unique_key}"
            )

        seen.add(unique_key)
        scenario_runs[scenario].add(run)

        if report_size != 1024:
            fail(
                f"CSV row {row_number}: "
                f"report_size_bytes={report_size}"
            )

        if accepted_count != n:
            fail(
                f"CSV row {row_number}: "
                f"accepted_count={accepted_count}, n={n}"
            )

        if row["correctness"] != "true":
            fail(
                f"CSV row {row_number}: "
                "correctness is not true"
            )

        for field in BLANK_FIELDS:
            if row[field] != "":
                fail(
                    f"CSV row {row_number}: "
                    f"{field} must be blank"
                )

        times = {
            field: parse_int(
                row[field],
                field,
                row_number,
            )
            for field in TIME_FIELDS
        }

        for field in {
            "sign_ns",
            "sigverify_ns",
            "aggregate_ns",
            "aggverify_ns",
            "total_crypto_ns",
        }:
            if times[field] <= 0:
                fail(
                    f"CSV row {row_number}: "
                    f"{field} must be positive"
                )

        if experiment == "size_sweep":
            if ns != 0:
                fail(
                    f"CSV row {row_number}: "
                    "size_sweep must have ns=0"
                )

            if times["privacy_ns"] != 0:
                fail(
                    f"CSV row {row_number}: "
                    "size_sweep privacy_ns must be zero"
                )
        else:
            if ns <= 0:
                fail(
                    f"CSV row {row_number}: "
                    "sensitive_sweep must have ns>0"
                )

            if times["privacy_ns"] <= 0:
                fail(
                    f"CSV row {row_number}: "
                    "sensitive_sweep privacy_ns "
                    "must be positive"
                )

        expected_total = (
            times["sign_ns"]
            + times["privacy_ns"]
            + times["sigverify_ns"]
            + times["aggregate_ns"]
            + times["aggverify_ns"]
        )

        if times["total_crypto_ns"] != expected_total:
            fail(
                f"CSV row {row_number}: "
                "total_crypto_ns mismatch; "
                f"expected {expected_total}, "
                f"found {times['total_crypto_ns']}"
            )

    actual_scenarios = set(scenario_runs)

    if actual_scenarios != expected_scenarios:
        fail(
            "Scenario set mismatch.\n"
            f"Expected: {sorted(expected_scenarios)}\n"
            f"Found:    {sorted(actual_scenarios)}"
        )

    expected_run_set = set(
        range(1, measurement_runs + 1)
    )

    for scenario in sorted(expected_scenarios):
        actual_runs = scenario_runs[scenario]

        if actual_runs != expected_run_set:
            fail(
                f"Scenario {scenario}: run set mismatch; "
                f"expected {sorted(expected_run_set)}, "
                f"found {sorted(actual_runs)}"
            )

    return len(rows), len(actual_scenarios)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: validate_dvas_crypto.py "
            "<result-directory> <smoke|full>",
            file=sys.stderr,
        )
        return 2

    result_directory = (
        Path(sys.argv[1])
        .expanduser()
        .resolve()
    )

    profile = sys.argv[2].lower()

    if profile not in PROFILE_CONFIG:
        fail(
            f"Unknown profile: {profile!r}"
        )

    if not result_directory.is_dir():
        fail(
            "Result directory does not exist: "
            f"{result_directory}"
        )

    rows, scenarios = validate_csv(
        result_directory / CSV_NAME,
        profile,
    )

    metadata = parse_key_value_file(
        result_directory / METADATA_NAME
    )

    internal_validation = parse_key_value_file(
        result_directory / VALIDATION_NAME
    )

    validate_metadata(
        metadata,
        profile,
        rows,
        scenarios,
    )

    validate_internal_validation(
        internal_validation,
        profile,
        rows,
        scenarios,
    )

    print("DVAS crypto CSV validation: PASS")
    print(f"profile={profile}")
    print(f"rows={rows}")
    print(
        "measurement_runs="
        f"{PROFILE_CONFIG[profile]['measurement_runs']}"
    )
    print(f"scenarios={scenarios}")
    print("report_size_bytes=1024")
    print("all_correctness=true")
    print("total_crypto_sum_check=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(
            f"DVAS crypto CSV validation: FAIL: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
