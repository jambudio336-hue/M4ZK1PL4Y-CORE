from __future__ import annotations
import re, tempfile, pathlib
from .base import Finding, Module


class SQLi(Module):
    name = "sqli"
    phase = 7

    async def run(self):
        ctx = self.ctx
        urls = await ctx.store.get_state(ctx.job_id, "param_urls") or []
        findings = []
        for url in urls[:120]:
            ctx.check()
            tmp = pathlib.Path(tempfile.mkdtemp())
            rc, out, err = await self.tool([
                "sqlmap", "-u", url, "--batch", "--smart", "--disable-coloring",
                "--level", str(ctx.cfg.get("vuln.sqli_level", 3)),
                "--risk", str(ctx.cfg.get("vuln.sqli_risk", 2)),
                "--technique", "BEUSTQ", "--threads", "6",
                "--timeout", "25", "--retries", "1", "--output-dir", str(tmp)],
                timeout=700)
            blob = out + err
            if "is vulnerable" not in blob.lower():
                continue
            param = (re.search(r"Parameter:\s*([^\s(]+)", blob) or [None, "?"])[1]
            findings.append(await self.emit(Finding(
                kind="sqli", title=f"SQL injection pada '{param}'",
                target=url, severity="critical", confidence="tentative",
                evidence=blob[-1800:],
                repro=[f"sqlmap -u '{url}' -p {param} --batch --dump"],
                poc=f"sqlmap -u '{url}' -p {param} --batch --level 3 --risk 2 --dump",
                data={"vector": "sqli", "url": url, "param": param})))
        return findings

    async def verify(self, f: Finding) -> bool:
        rc, out, err = await self.tool(
            ["sqlmap", "-u", f.data["url"], "-p", f.data["param"], "--batch",
             "--smart", "--disable-coloring", "--timeout", "20"], timeout=420)
        ok = "is vulnerable" in (out + err).lower()
        f.hits = 1 if ok else 0
        return ok
