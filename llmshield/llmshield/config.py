from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    provider: str = 'mock'
    model: str = ''

    @classmethod
    def from_env(cls):
        return cls(Path(os.getenv('LLMSHIELD_DATA_DIR', 'data')).resolve(),
                   os.getenv('LLMSHIELD_PROVIDER', 'mock'), os.getenv('LLMSHIELD_MODEL', ''))
