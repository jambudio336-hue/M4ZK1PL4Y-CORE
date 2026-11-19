from __future__ import annotations
import os, pathlib, socket, yaml
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _detect_callback() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return "" if ip.startswith("127.") else ip
    except Exception:
        return ""


@dataclass
class Settings:
    raw: dict = field(default_factory=dict)

    def __post_init__(self):
        self.raw = yaml.safe_load((ROOT / "config" / "default.yaml").read_text()) or {}
        if os.getenv("M4Z_SAFE_MODE", "").lower() in ("1", "true"):
            self.raw.setdefault("app", {})["safe_mode"] = True
        if not self.get("app.callback_host"):
            self.raw["app"]["callback_host"] = _detect_callback()

    def get(self, path, default=None):
        cur = self.raw
        for p in path.split("."):
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
        return cur


settings = Settings()
REPORTS = ROOT / "reports"; REPORTS.mkdir(exist_ok=True)
DATA = ROOT / "data"; DATA.mkdir(exist_ok=True)
