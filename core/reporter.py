"""Report-Ausgabe in TXT, JSON und HTML — inkl. Befunde-Erklaerungen und
Behebungshinweisen aus core.remediation."""
import json
from datetime import datetime

from core.remediation import iter_findings, advice_for

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Reporter:
    @staticmethod
    def _counts(results):
        c = {"PASS": 0, "FAIL": 0, "WARN": 0, "OTHER": 0}
        for r in results:
            s = r["status"]
            c[s if s in c else "OTHER"] += 1
        return c

    @staticmethod
    def save_txt(results, filepath):
        c = Reporter._counts(results)
        lines = ["=" * 60, "SECURITY AUDIT REPORT", f"Datum: {datetime.now().isoformat(timespec='seconds')}", "=" * 60, ""]
        lines.append("ERGEBNISSE")
        lines.append("-" * 60)
        for r in results:
            lines.append(f"[{r['status']}] {r['test_id']} ({r['title']}): {r['message']}")
        lines += ["", "=" * 60,
                  f"ZUSAMMENFASSUNG   PASS: {c['PASS']}  |  FAIL: {c['FAIL']}  |  WARN: {c['WARN']}  |  OTHER: {c['OTHER']}",
                  "=" * 60, ""]

        findings = list(iter_findings(results))
        if findings:
            lines += ["BEFUNDE & EMPFEHLUNGEN", "=" * 60, ""]
            for f in findings:
                lines.append(f"[{f['status']}] {f['test_id']}: {f['title']}  (Schwere: {f['severity']})")
                lines.append(f"   Befund:   {f['message']}")
                lines.append(f"   Ursache:  {f['explanation']}")
                lines.append(f"   Behebung: {f['remediation']}")
                lines.append("")
        else:
            lines += ["Keine FAIL-/WARN-Befunde — nichts zu beheben.", ""]

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    @staticmethod
    def save_json(results, filepath):
        # Ergebnisse um Erklaerung/Behebung anreichern (fuer FAIL/WARN am relevantesten).
        enriched = []
        for r in results:
            item = dict(r)
            if r["status"] in ("FAIL", "WARN"):
                a = advice_for(r["test_id"])
                item["explanation"] = a["explanation"]
                item["remediation"] = a["remediation"]
            enriched.append(item)
        payload = {
            "date": datetime.now().isoformat(timespec="seconds"),
            "summary": Reporter._counts(results),
            "results": enriched,
            "findings": list(iter_findings(results)),
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    @staticmethod
    def save_html(results, filepath):
        c = Reporter._counts(results)
        colors = {"PASS": "#1f8a5f", "FAIL": "#b3261e", "WARN": "#b7791f", "BLOCKED": "#55607a",
                  "TOOL_ERROR": "#b3261e", "NOT_APPLICABLE": "#55607a", "SKIPPED": "#55607a",
                  "INFO": "#1b3a5c", "ERROR": "#b3261e"}
        rows = ""
        for r in results:
            col = colors.get(r["status"], "#1a1a2e")
            rows += (f'<tr><td>{r["test_id"]}</td><td>{_esc(r["title"])}</td>'
                     f'<td style="color:{col};font-weight:700">{r["status"]}</td>'
                     f'<td>{_esc(r["severity"])}</td><td>{_esc(r["message"])}</td></tr>')

        findings = list(iter_findings(results))
        cards = ""
        for f in findings:
            col = colors.get(f["status"], "#1a1a2e")
            cards += (
                f'<div class="finding">'
                f'<div class="fh"><span class="badge" style="background:{col}">{f["status"]}</span>'
                f'<b>{f["test_id"]}</b> — {_esc(f["title"])} <span class="sev">Schwere: {_esc(f["severity"])}</span></div>'
                f'<div class="frow"><span>Befund</span><p>{_esc(f["message"])}</p></div>'
                f'<div class="frow"><span>Ursache</span><p>{_esc(f["explanation"])}</p></div>'
                f'<div class="frow"><span>Behebung</span><p>{_esc(f["remediation"])}</p></div>'
                f'</div>')
        if not findings:
            cards = '<p class="ok">Keine FAIL-/WARN-Befunde — nichts zu beheben.</p>'

        html = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<title>Security Audit Report</title>
<style>
 body{{font-family:system-ui,'Segoe UI',sans-serif;background:#eef1f5;color:#1a1a2e;margin:0;padding:32px}}
 h1{{color:#1b3a5c}} .meta{{color:#55607a;margin-bottom:20px}}
 .tiles{{display:flex;gap:10px;margin:16px 0 28px}}
 .tile{{flex:1;border-radius:12px;padding:12px 16px}} .tile b{{font-size:26px;display:block}}
 .p{{background:#e6f4ee;color:#1f8a5f}} .f{{background:#fbe9e8;color:#b3261e}}
 .w{{background:#fbf1e0;color:#b7791f}} .o{{background:#e7e9ee;color:#55607a}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}}
 th,td{{padding:9px 12px;border-bottom:1px solid #e1e6ee;text-align:left;font-size:14px}}
 th{{background:#1b3a5c;color:#fff}}
 h2{{color:#1b3a5c;margin-top:32px}}
 .finding{{background:#fff;border:1px solid #e1e6ee;border-left:4px solid #b3261e;border-radius:10px;padding:14px 16px;margin-bottom:12px}}
 .fh{{font-size:15px;margin-bottom:8px}} .badge{{color:#fff;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;margin-right:8px}}
 .sev{{color:#9aa2b1;font-size:12px;margin-left:8px}}
 .frow{{display:flex;gap:12px;margin:4px 0}} .frow span{{flex:none;width:90px;color:#55607a;font-weight:600;font-size:13px}}
 .frow p{{margin:0;font-size:14px}} .ok{{color:#1f8a5f;font-weight:600}}
</style></head><body>
<h1>Security Audit Report</h1>
<div class="meta">Datum: {datetime.now().isoformat(timespec='seconds')}</div>
<div class="tiles">
 <div class="tile p"><b>{c['PASS']}</b>PASS</div><div class="tile f"><b>{c['FAIL']}</b>FAIL</div>
 <div class="tile w"><b>{c['WARN']}</b>WARN</div><div class="tile o"><b>{c['OTHER']}</b>OTHER</div>
</div>
<table><tr><th>ID</th><th>Test</th><th>Status</th><th>Schwere</th><th>Meldung</th></tr>{rows}</table>
<h2>Befunde &amp; Empfehlungen</h2>
{cards}
</body></html>"""
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))
