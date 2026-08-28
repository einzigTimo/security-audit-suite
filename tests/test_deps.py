"""Bekannte verwundbare Frontend-Bibliotheken anhand eingebundener Versionen."""
import re
from core.base_test import BaseTest, Http, body_of

# Minimalversionen, unterhalb derer oeffentlich bekannte CVEs bestehen.
KNOWN = {
    "jquery": (3, 5, 0),
    "angular": (1, 8, 0),
    "bootstrap": (4, 3, 1),
    "lodash": (4, 17, 21),
}


def _cmp(v, minimum):
    return tuple(v) < minimum


class VulnerableLibsTest(BaseTest):
    test_id = "DEP-01"; title = "Verwundbare JS-Bibliotheken"; severity = "medium"

    def run(self, ctx):
        h = Http(ctx)
        try:
            body = body_of(h.get(ctx["base_url"]))
        except Exception as e:
            return self.error(e)
        findings = []
        for lib, minimum in KNOWN.items():
            m = re.search(lib + r"[-.@/]?(\d+)\.(\d+)\.(\d+)", body, re.I)
            if m:
                ver = tuple(int(x) for x in m.groups())
                if _cmp(ver, minimum):
                    findings.append(f"{lib} {'.'.join(map(str, ver))}")
        if findings:
            return self.fail("Veraltete Bibliotheken mit bekannten CVEs: " + ", ".join(findings))
        return self.ok("Keine bekannten verwundbaren Bibliotheksversionen erkannt.")
