"""Check represented lifecycle/session/TLS invariants in authorized benchmark evidence."""

import argparse
import json
from pathlib import Path
from xml.etree import ElementTree

from pydantic import BaseModel, Field


class Failure(BaseModel, extra="forbid"):
    source: str
    line: int
    invariant: str
    identity: str


class ProbeReport(BaseModel, extra="forbid"):
    scope: str = "Rendered benchmark evidence; equal millisecond timestamps are unordered"
    process_rows: int = 0
    transitions: int = 0
    netonly_children: int = 0
    tls_rows: int = 0
    native_forks: int = 0
    failures: list[Failure] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Return whether every observed relationship satisfied its invariant."""
        return not self.failures


def probe(data: Path) -> ProbeReport:
    """Inspect only the explicitly supplied, already authorized data directory."""
    report = ProbeReport()
    for path in sorted(data.rglob("ecar.json")):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        processes = [
            (line, row | row.get("properties", {}))
            for line, row in enumerate(rows, 1)
            if row.get("object") == "PROCESS"
        ]
        report.process_rows += len(processes)
        report.transitions += sum(row["action"] == "MODIFY" for _, row in processes)
        births = {row["objectID"]: row for _, row in processes if row["action"] == "CREATE"}
        closes = {row["objectID"]: row for _, row in processes if row["action"] == "TERMINATE"}
        for line, row in processes:
            birth = births.get(row["objectID"])
            close = closes.get(row["objectID"])
            parent = births.get(row.get("parentObjectID", row.get("actorID")))
            checks = [
                (
                    birth is not None and row["timestamp_ms"] < birth["timestamp_ms"],
                    "process observation precedes explicit visible birth",
                ),
                (
                    close is not None and row["timestamp_ms"] > close["timestamp_ms"],
                    "process observation follows explicit visible close",
                ),
                (
                    row["action"] == "CREATE"
                    and parent is not None
                    and row["timestamp_ms"] < parent["timestamp_ms"],
                    "child birth precedes explicit visible parent birth",
                ),
            ]
            for failed, invariant in checks:
                if failed:
                    report.failures.append(
                        Failure(
                            source=str(path.relative_to(data)),
                            line=line,
                            invariant=invariant,
                            identity=str(row["objectID"]),
                        )
                    )

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    for path in sorted(data.rglob("windows_event_sysmon.xml")):
        events = ElementTree.parse(path).getroot()
        creates: list[dict[str, str]] = []
        for event in events:
            if event.findtext("e:System/e:EventID", namespaces=ns) != "1":
                continue
            fields = {
                item.attrib["Name"]: item.text or ""
                for item in event.findall("e:EventData/e:Data", ns)
            }
            fields["record"] = event.findtext("e:System/e:EventRecordID", namespaces=ns) or "0"
            creates.append(fields)
        parents = {
            row.get("ProcessGuid"): row
            for row in creates
            if row.get("Image", "").lower().endswith("\\runas.exe")
            and "/netonly" in row.get("CommandLine", "").lower()
        }
        for row in creates:
            parent = parents.get(row.get("ParentProcessGuid"))
            if parent is None:
                continue
            report.netonly_children += 1
            if row.get("TerminalSessionId") != parent.get("TerminalSessionId"):
                report.failures.append(
                    Failure(
                        source=str(path.relative_to(data)),
                        line=int(row["record"]),
                        invariant="netonly child changed terminal session (line is EventRecordID)",
                        identity=row.get("ProcessGuid", ""),
                    )
                )

    for path in sorted(data.rglob("ssl.json")):
        conn_path = path.with_name("conn.json")
        if not conn_path.exists():
            continue  # No selected transport evidence cannot establish a contradiction.
        connections = {
            row["uid"]: row
            for row in (json.loads(line) for line in conn_path.read_text().splitlines())
        }
        for line, raw in enumerate(path.read_text().splitlines(), 1):
            row = json.loads(raw)
            report.tls_rows += 1
            connection = connections.get(row["uid"])
            if connection is None:
                continue
            history = row.get("ssl_history", "")
            contradiction = "S" in history and not connection.get("resp_bytes", 0)
            missing_exchange = (
                row.get("version") == "TLSv12"
                and row.get("established")
                and not row.get("resumed")
                and "ECDHE" in row.get("cipher", "")
                and "K" not in history
                and not connection.get("missed_bytes", 0)
            )
            if contradiction or missing_exchange:
                report.failures.append(
                    Failure(
                        source=str(path.relative_to(data)),
                        line=line,
                        identity=row["uid"],
                        invariant=(
                            "ServerHello without responder payload"
                            if contradiction
                            else "full ECDHE handshake lacks server key exchange"
                        ),
                    )
                )
    for path in sorted(data.rglob("macos_endpoint_security.ndjson")):
        for raw in path.read_text().splitlines():
            report.native_forks += json.loads(raw).get("event_type") == 11
    return report


def main() -> None:
    """Write a reproducible invariant report without displaying evidence records."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.data.resolve(strict=True)
    if not data.is_dir():
        parser.error("data must be the authorized evidence directory")
    report = probe(data)
    payload = report.model_dump() | {"passed": report.passed}
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"passed={report.passed} failures={len(report.failures)} native_forks={report.native_forks}"
    )
    raise SystemExit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
