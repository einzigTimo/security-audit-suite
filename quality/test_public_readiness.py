import ast
import hashlib
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from core.updater import UpdateVerificationError, parse_sha256, verify_sha256
from core.inventory import local_project_inventory
from core.policy import build_policy
from public_readiness import scan


class ActiveMethodVisitor(ast.NodeVisitor):
    def __init__(self):
        self.class_gate = False
        self.guard = False
        self.violations = []

    def visit_ClassDef(self, node):
        previous = self.class_gate
        self.class_gate = any(
            isinstance(item, (ast.Assign, ast.AnnAssign))
            and any(
                isinstance(target, ast.Name) and target.id == "requires_aggressive"
                for target in getattr(item, "targets", [getattr(item, "target", None)])
            )
            and isinstance(getattr(item, "value", None), ast.Constant)
            and item.value.value is True
            for item in node.body
        )
        self.generic_visit(node)
        self.class_gate = previous

    def visit_If(self, node):
        previous = self.guard
        active_guard = "aggressive" in ast.unparse(node.test)
        self.guard = previous or active_guard
        for item in node.body:
            self.visit(item)
        self.guard = previous
        for item in node.orelse:
            self.visit(item)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "fetch":
            for keyword in node.keywords:
                if keyword.arg == "method" and isinstance(keyword.value, ast.Constant):
                    if str(keyword.value.value).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                        if not (self.class_gate or self.guard):
                            self.violations.append(node.lineno)
        self.generic_visit(node)


class PublicReadinessTests(unittest.TestCase):
    def test_repository_scan_is_clean(self):
        self.assertEqual([], scan(ROOT))

    def test_test_scope_is_not_reduced(self):
        count = 0
        for path in (ROOT / "tests").glob("test_*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
            count += sum(
                isinstance(node, ast.ClassDef)
                and any(isinstance(base, ast.Name) and base.id == "BaseTest" for base in node.bases)
                for node in tree.body
            )
        self.assertGreaterEqual(count, 46)

    def test_active_requests_are_gated(self):
        for path in (ROOT / "tests").glob("test_*.py"):
            visitor = ActiveMethodVisitor()
            visitor.visit(ast.parse(path.read_text(encoding="utf-8-sig")))
            self.assertEqual([], visitor.violations, path.name)
        helper = (ROOT / "core" / "base_test.py").read_text(encoding="utf-8")
        self.assertIn('{"POST", "PUT", "PATCH", "DELETE"}', helper)
        self.assertIn("not self._active_allowed", helper)

    def test_target_and_consent_lifecycle(self):
        source = (ROOT / "gui.pyw").read_text(encoding="utf-8")
        self.assertIn("self.url_var = tk.StringVar()", source)
        self.assertNotIn("tk.StringVar(value=\"http", source)
        start = source[source.index("    def start(self):"):source.index("    def _run_engine(self):")]
        detect = source[source.index("    def auto_detect(self):"):source.index("    def _run_detect(self, url):")]
        self.assertLess(start.index('self.url_var.set("")'), start.index("AuditEngine(config)"))
        self.assertLess(detect.index("consent_var.get()"), detect.index("threading.Thread"))
        self.assertLess(detect.index('self.url_var.set("")'), detect.index("threading.Thread"))

    def test_updater_checksum_binding(self):
        payload = b"verified update"
        expected = hashlib.sha256(payload).hexdigest()
        self.assertEqual(expected, parse_sha256(f"{expected}  setup.exe", "setup.exe"))
        with patch("core.updater.sha256_file", return_value=expected):
            self.assertTrue(verify_sha256("setup.exe", expected))
        with patch("core.updater.sha256_file", return_value="0" * 64):
            with self.assertRaises(UpdateVerificationError):
                verify_sha256("setup.exe", expected)

    def test_dynamic_modules_are_bundled(self):
        spec = (ROOT / "packaging" / "security-audit-suite.spec").read_text(encoding="utf-8")
        self.assertIn('collect_submodules("core")', spec)
        self.assertIn('collect_submodules("tests")', spec)

    def test_level_four_is_max_effort(self):
        read_policy = build_policy(read_level=4, write_level=0, inventory_mode="quick")
        write_policy = build_policy(read_level=1, write_level=4, inventory_mode="full")
        self.assertEqual("Deep (Insane - Time-Based)", read_policy.legacy_intensity)
        self.assertTrue(read_policy.max_effort)
        self.assertTrue(write_policy.aggressive)
        self.assertEqual(10, write_policy.aggression)
        self.assertEqual("full", write_policy.inventory_mode)

    def test_inventory_quick_and_full_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "app.py"
            sample.write_text("print('ok')\n", encoding="utf-8")
            quick = local_project_inventory(root, mode="quick")
            full = local_project_inventory(root, mode="full")
        quick_file = next(item for item in quick if item.relative_path == "app.py")
        full_file = next(item for item in full if item.relative_path == "app.py")
        self.assertIsNone(quick_file.sha256)
        self.assertRegex(full_file.sha256 or "", r"^[0-9a-f]{64}$")
        self.assertNotIn(":", full_file.relative_path)
        self.assertNotIn("\\", full_file.relative_path)


if __name__ == "__main__":
    unittest.main()
