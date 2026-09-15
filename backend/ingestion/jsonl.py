from __future__ import annotations
import json
from collections.abc import Iterator
from pathlib import Path
from pydantic import ValidationError
from .models import FlowEvent

class JSONLIngestor:
    """Read-only deterministic JSONL flow ingestion."""
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def events(self) -> Iterator[FlowEvent]:
        with self.path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    yield FlowEvent.model_validate(json.loads(line))
                except (json.JSONDecodeError, ValidationError) as exc:
                    raise ValueError(f"invalid JSONL record at line {line_no}") from exc
