from __future__ import annotations
import re, uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import Finding, Module, body_hash, similarity

IDP = re.compile(r"^(id|uid|user_?id|account|acc|order|invoice|doc|file|pid|no|num|ref)$", re.I)


def mutate(v: str, i: int) -> str | None:
    if v.isdigit():
        n = int(v)
        return str(n + 1 if i % 2 else max(n - 1, 1))
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", v, re.I):
        return str(uuid.uuid4())
    if re.fullmatch(r"[0-9a-f]{16,64}", v, re.I):
        return uuid.uuid4().hex[:len(v)]
    return None


class IDOR(Module):
    name = "idor"
    phase = 7

    async def run(self):
        urls = await self.ctx.store.get_state(self.ctx.job_id, "param_urls") or []
        findings = []
        for url in urls[:150]:
            self.ctx.check()
            q = parse_qs(urlparse(url).query)
            keys = [k for k in q if IDP.match(k)]
            if not keys:
                continue
            try:
                base = await self.ctx.http.get(url, timeout=12)
            except Exception:
                continue
            for k in keys:
                orig = q[k][0]
                for i in range(min(self.ctx.cfg.get("vuln.idor_mutations", 24), 12)):
                    m = mutate(orig, i)
                    if not m or m == orig:
                        continue
                    qq = dict(q); qq[k] = [m]
                    nu = urlunparse(urlparse(url)._replace(query=urlencode(qq, doseq=True)))
                    try:
                        r = await self.ctx.http.get(nu, timeout=12)
                    except Exception:
                        continue
                    sim = similarity(base.text, r.text)
                    if (base.status_code == r.status_code == 200 and len(r.content) > 300
                            and body_hash(r.text) != body_hash(base.text) and 0.2 < sim < 0.96):
                        findings.append(await self.emit(Finding(
                            kind="idor", title=f"IDOR kandidat '{k}' ({orig}→{m})",
                            target=nu, severity="high", confidence="tentative",
                            evidence=f"status sama, hash beda, kemiripan {sim:.2f}",
                            repro=[f"curl -s '{url}' | sha256sum", f"curl -s '{nu}' | sha256sum"],
                            poc=f"curl -s '{nu}'",
                            data={"vector": "idor", "url": url, "mutated": nu,
                                  "param": k, "sim": sim})))
                        break
                break
        return findings

    async def verify(self, f: Finding) -> bool:
        try:
            a = await self.ctx.http.get(f.data["url"], timeout=12)
            b = await self.ctx.http.get(f.data["mutated"], timeout=12)
            return (a.status_code == b.status_code == 200
                    and body_hash(a.text) != body_hash(b.text)
                    and 0.2 < similarity(a.text, b.text) < 0.96)
        except Exception:
            return False
