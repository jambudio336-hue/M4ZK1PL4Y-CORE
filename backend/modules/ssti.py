from __future__ import annotations
from .base import Finding, Module, marker

MATRIX = [
    ("jinja2", "{{%s}}", "7*7"),
    ("twig", "{{%s}}", "7*7"),
    ("freemarker", "${{%s}}", "7*7"),
    ("velocity", "#set($x=%s)$x", "7*7"),
    ("erb", "<%%= %s %%>", "7*7"),
    ("smarty", "{%s}", "7*7"),
]


class SSTI(Module):
    name = "ssti"
    phase = 7

    async def run(self):
        urls = await self.ctx.store.get_state(self.ctx.job_id, "param_urls") or []
        findings = []
        for url in urls[:100]:
            self.ctx.check()
            for eng, tpl, expr in MATRIX:
                m = marker()
                payload = tpl % expr
                inj = url + ("&" if "?" in url else "?") + f"x={payload}"
                try:
                    r = await self.ctx.http.get(inj, timeout=12)
                except Exception:
                    continue
                if "49" in r.text:
                    findings.append(await self.emit(Finding(
                        kind="ssti", title=f"Template injection ({eng})",
                        target=inj, severity="critical", confidence="tentative",
                        evidence=f"payload {payload} → 49 terefleksi",
                        repro=[f"curl -s '{inj}' | grep 49"],
                        poc=f"curl -s '{inj}'",
                        data={"engine": eng, "url": inj, "payload": payload})))
                    break
        return findings

    async def verify(self, f: Finding) -> bool:
        try:
            r = await self.ctx.http.get(f.target, timeout=12)
            return "49" in r.text
        except Exception:
            return False
