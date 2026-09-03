"""Benchmark optional codecs and compressors on one real incremental checkpoint delta.

The input is a retained generation output root containing two recovery manifests. The harness
loads only heads and segments newly reachable from the latest recovery, runs every available
combination in isolated fresh processes, and never changes project dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import statistics
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidenceforge.generation.checkpoints.models import CheckpointManifest
from evidenceforge.generation.checkpoints.packed import PACKED_DOCUMENT_MAGIC
from evidenceforge.generation.checkpoints.packed import dumps as packed_dumps
from evidenceforge.generation.checkpoints.packed import loads as packed_loads
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore

_RESULT_PREFIX = "EFORGE_INCREMENTAL_CODEC_RESULT="
_CODECS = ("stdlib-packed", "msgspec-msgpack", "numpy-npy", "arrow-ipc")
_COMPRESSORS = ("none", "zlib-1", "lz4-frame", "zstd-1-single", "zstd-1-multithread")


@dataclass(frozen=True)
class _Workload:
    documents: tuple[object, ...]
    raw_buffers: tuple[bytes, ...]
    source_bytes: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _workspace(output_root: Path) -> Path:
    workspace = output_root / ".eforge-generation"
    if not workspace.is_dir():
        raise ValueError(f"output root has no retained checkpoint workspace: {output_root}")
    return workspace


def _manifest(workspace: Path, sequence: int) -> CheckpointManifest:
    path = workspace / "recovery" / f"{sequence:020d}" / "manifest.json"
    return CheckpointManifest.model_validate_json(path.read_bytes())


def _load_workload(output_root: Path) -> _Workload:
    workspace = _workspace(output_root)
    index = json.loads((workspace / "CURRENT.json").read_bytes())
    recoveries = index.get("recoveries") if type(index) is dict else None
    if type(recoveries) is not list or len(recoveries) != 2:
        raise ValueError("codec benchmark requires exactly two retained recoveries")
    sequences = [row.get("sequence") for row in recoveries if type(row) is dict]
    if len(sequences) != 2 or any(type(value) is not int for value in sequences):
        raise ValueError("checkpoint recovery index is invalid")
    latest = _manifest(workspace, sequences[0])
    previous = _manifest(workspace, sequences[1])
    store = IncrementalCheckpointStore(output_root)
    latest_segments = store.segment_references(latest)
    previous_hashes = {reference.sha256 for reference in store.segment_references(previous)}
    new_segments = tuple(
        reference for reference in latest_segments if reference.sha256 not in previous_hashes
    )

    payloads: list[bytes] = []
    for head in latest.participant_heads:
        path = workspace.joinpath(*Path(head.relative_path).parts)
        payload = path.read_bytes()
        if len(payload) != head.size or _sha256(payload) != head.sha256:
            raise ValueError(f"checkpoint head failed validation: {head.owner}")
        payloads.append(payload)
    payloads.extend(store.read_segment(reference) for reference in new_segments)

    documents: list[object] = []
    raw_buffers: list[bytes] = []
    for payload in payloads:
        if payload.startswith(PACKED_DOCUMENT_MAGIC):
            documents.append(packed_loads(payload))
        else:
            raw_buffers.append(payload)
    if not documents:
        raise ValueError("checkpoint delta contains no packed documents")
    return _Workload(
        documents=tuple(documents),
        raw_buffers=tuple(raw_buffers),
        source_bytes=sum(len(payload) for payload in payloads),
    )


def _encode(codec: str, value: object) -> bytes:
    if codec == "stdlib-packed":
        return packed_dumps(value)
    if codec == "msgspec-msgpack":
        import msgspec

        return msgspec.msgpack.encode(value, order="deterministic")
    if codec == "numpy-npy":
        import io

        import numpy as np

        stream = io.BytesIO()
        np.save(stream, np.frombuffer(packed_dumps(value), dtype=np.uint8), allow_pickle=False)
        return stream.getvalue()
    if codec == "arrow-ipc":
        import pyarrow as pa
        import pyarrow.ipc as ipc

        packed = packed_dumps(value)
        table = pa.table({"packed_document": pa.array([packed], type=pa.binary())})
        sink = pa.BufferOutputStream()
        with ipc.new_file(sink, table.schema) as writer:
            writer.write_table(table)
        return sink.getvalue().to_pybytes()
    raise ValueError(f"unknown checkpoint codec: {codec}")


def _decode(codec: str, payload: bytes) -> object:
    if codec == "stdlib-packed":
        return packed_loads(payload)
    if codec == "msgspec-msgpack":
        import msgspec

        return msgspec.msgpack.decode(payload)
    if codec == "numpy-npy":
        import io

        import numpy as np

        array = np.load(io.BytesIO(payload), allow_pickle=False)
        if array.dtype != np.dtype("uint8") or array.ndim != 1:
            raise ValueError("NumPy candidate returned a non-primitive array")
        return packed_loads(array.tobytes())
    if codec == "arrow-ipc":
        import pyarrow as pa
        import pyarrow.ipc as ipc

        with ipc.open_file(pa.BufferReader(payload)) as reader:
            table = reader.read_all()
        if table.column_names != ["packed_document"] or table.num_rows != 1:
            raise ValueError("Arrow candidate returned an invalid primitive table")
        packed = table.column(0)[0].as_py()
        if type(packed) is not bytes:
            raise ValueError("Arrow candidate returned a non-binary document")
        return packed_loads(packed)
    raise ValueError(f"unknown checkpoint codec: {codec}")


def _compressor(name: str) -> tuple[Any, Any]:
    if name == "none":
        return (lambda payload: payload), (lambda payload: payload)
    if name == "zlib-1":
        return (lambda payload: zlib.compress(payload, level=1)), zlib.decompress
    if name == "lz4-frame":
        import lz4.frame

        return (
            lambda payload: lz4.frame.compress(payload, compression_level=0),
            lz4.frame.decompress,
        )
    if name in {"zstd-1-single", "zstd-1-multithread"}:
        import zstandard

        threads = 0 if name == "zstd-1-single" else -1
        compressor = zstandard.ZstdCompressor(level=1, threads=threads)
        decompressor = zstandard.ZstdDecompressor()
        return compressor.compress, decompressor.decompress
    raise ValueError(f"unknown checkpoint compressor: {name}")


def _peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _run_child(output_root: Path, codec: str, compression: str) -> dict[str, object]:
    workload = _load_workload(output_root)
    encode_started = time.perf_counter()
    encoded_documents = tuple(_encode(codec, document) for document in workload.documents)
    encode_seconds = time.perf_counter() - encode_started
    for document, payload in zip(workload.documents, encoded_documents, strict=True):
        if _encode(codec, document) != payload:
            raise ValueError(f"{codec} encoding is not deterministic")

    compress, decompress = _compressor(compression)
    buffers = (*encoded_documents, *workload.raw_buffers)
    compression_started = time.perf_counter()
    compressed = tuple(compress(payload) for payload in buffers)
    compression_seconds = time.perf_counter() - compression_started
    hash_started = time.perf_counter()
    digest = hashlib.sha256()
    for payload in compressed:
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    digest_value = digest.hexdigest()
    hash_seconds = time.perf_counter() - hash_started

    decompression_started = time.perf_counter()
    decoded_buffers = tuple(decompress(payload) for payload in compressed)
    decompression_seconds = time.perf_counter() - decompression_started
    if decoded_buffers != buffers:
        raise ValueError(f"{compression} changed checkpoint bytes")
    decode_started = time.perf_counter()
    decoded_documents = tuple(
        _decode(codec, payload) for payload in decoded_buffers[: len(encoded_documents)]
    )
    decode_seconds = time.perf_counter() - decode_started
    if decoded_documents != workload.documents:
        raise ValueError(f"{codec} changed checkpoint semantics")
    return {
        "codec": codec,
        "compression": compression,
        "compressed_bytes": sum(len(payload) for payload in compressed),
        "decode_seconds": decode_seconds,
        "decompression_seconds": decompression_seconds,
        "digest": digest_value,
        "encode_seconds": encode_seconds,
        "encoded_bytes": sum(len(payload) for payload in buffers),
        "hash_seconds": hash_seconds,
        "peak_rss_bytes": _peak_rss_bytes(),
        "source_bytes": workload.source_bytes,
        "write_work_seconds": encode_seconds + compression_seconds + hash_seconds,
        "compression_seconds": compression_seconds,
    }


def _child_command(args: argparse.Namespace, codec: str, compression: str) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).resolve()),
        str(args.output_root),
        "--trials",
        "1",
        "--child-codec",
        codec,
        "--child-compression",
        compression,
    ]


def _invoke_child(args: argparse.Namespace, codec: str, compression: str) -> dict[str, object]:
    completed = subprocess.run(
        _child_command(args, codec, compression),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return {
            "codec": codec,
            "compression": compression,
            "error": completed.stderr.strip() or completed.stdout.strip(),
        }
    line = next(
        (
            item
            for item in reversed(completed.stdout.splitlines())
            if item.startswith(_RESULT_PREFIX)
        ),
        None,
    )
    if line is None:
        raise RuntimeError("codec benchmark child returned no structured result")
    value = json.loads(line.removeprefix(_RESULT_PREFIX))
    if type(value) is not dict:
        raise RuntimeError("codec benchmark child returned an invalid result")
    return value


def _median(rows: list[dict[str, object]], field: str) -> float:
    return statistics.median(float(row[field]) for row in rows)


def _run_parent(args: argparse.Namespace) -> dict[str, object]:
    combinations = [(codec, compression) for codec in _CODECS for compression in _COMPRESSORS]
    trials: list[dict[str, object]] = []
    for trial in range(args.trials):
        offset = trial % len(combinations)
        rotated = combinations[offset:] + combinations[:offset]
        for codec, compression in rotated:
            result = _invoke_child(args, codec, compression)
            result["trial"] = trial + 1
            trials.append(result)

    results: list[dict[str, object]] = []
    for codec, compression in combinations:
        rows = [
            row for row in trials if row["codec"] == codec and row["compression"] == compression
        ]
        errors = [str(row["error"]) for row in rows if "error" in row]
        if errors:
            results.append(
                {
                    "codec": codec,
                    "compression": compression,
                    "errors": errors,
                    "status": "unavailable-or-incompatible",
                }
            )
            continue
        digests = {str(row["digest"]) for row in rows}
        if len(digests) != 1:
            raise RuntimeError(f"{codec}/{compression} output was not deterministic")
        results.append(
            {
                "codec": codec,
                "compression": compression,
                "compressed_bytes": int(rows[0]["compressed_bytes"]),
                "decode_seconds_median": _median(rows, "decode_seconds"),
                "decompression_seconds_median": _median(rows, "decompression_seconds"),
                "encode_seconds_median": _median(rows, "encode_seconds"),
                "encoded_bytes": int(rows[0]["encoded_bytes"]),
                "hash_seconds_median": _median(rows, "hash_seconds"),
                "peak_rss_bytes_median": int(
                    statistics.median(int(row["peak_rss_bytes"]) for row in rows)
                ),
                "source_bytes": int(rows[0]["source_bytes"]),
                "status": "safe-round-trip",
                "write_work_seconds_median": _median(rows, "write_work_seconds"),
                "compression_seconds_median": _median(rows, "compression_seconds"),
            }
        )
    return {
        "output_root": str(args.output_root),
        "results": results,
        "trials": args.trials,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child-codec", choices=_CODECS, help=argparse.SUPPRESS)
    parser.add_argument("--child-compression", choices=_COMPRESSORS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    args.output_root = args.output_root.resolve()
    if not args.output_root.is_dir():
        parser.error(f"output root does not exist: {args.output_root}")
    if (args.child_codec is None) != (args.child_compression is None):
        parser.error("internal child codec and compression must be supplied together")
    return args


def main() -> int:
    args = _parse_args()
    if args.child_codec is not None:
        result = _run_child(args.output_root, args.child_codec, args.child_compression)
        print(_RESULT_PREFIX + json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    result = _run_parent(args)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
