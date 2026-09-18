import json
import logging
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger('llmshield.' + str(path.resolve()))
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if not self.logger.handlers:
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def emit(self, event: str, **fields):
        # Prompts and raw model responses deliberately stay out of the security log.
        self.logger.info(json.dumps({'timestamp': utcnow(), 'event': event, **fields}))
