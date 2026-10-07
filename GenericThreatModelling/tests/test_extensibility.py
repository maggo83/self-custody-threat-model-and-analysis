"""A new kind of entity and a threat on it are added through data alone: a copy of the knowledge files (ontology schema,
catalogs, lookups, texts) is extended, and the unchanged engine analyses a setup that uses the new class.

    python3 -m unittest discover -s GenericThreatModelling/tests -k Extensibility
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CLI = HERE.parent / "engine" / "threat_analysis.py"


def extend_knowledge(root):
    """A password manager: software on a computing device that keeps secrets behind a master password."""
    schema_path = root / "SetupOntology.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["x-classes"]["PasswordManager"] = {"collection": "password_managers", "placed_by": "runs_on", "inherits_status": True, "active": True}
    schema["properties"]["password_managers"] = {"type": "array", "items": {"$ref": "#/$defs/passwordManager"}}
    schema["$defs"]["passwordManager"] = {
        "type": "object", "additionalProperties": False, "required": ["id", "name", "runs_on", "stores"],
        "properties": {
            "id": {"$ref": "#/$defs/id"}, "name": {"type": "string"}, "comment": {"$ref": "#/$defs/comment"},
            "runs_on": {"$ref": "#/$defs/id", "x-ref": "ComputingDevice"},
            "master_password": {"$ref": "#/$defs/id", "x-ref": "PinPassword"},
            "stores": {"$ref": "#/$defs/idList", "x-ref": "Secret"},
        },
    }
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    data = root / "GenericThreatModelling"
    model_path = data / "AccessModel.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["derived"]["Secret.password_managers"] = {"select": "PasswordManager", "where": {"path": "$e.stores", "contains": "$self"}}
    model["derived"]["Secret.carriers"]["union"].append({"path": "password_managers[]"})
    model["derived"]["PasswordManager.holds"] = {"path": "stores[]"}
    model_path.write_text(json.dumps(model, indent=2), encoding="utf-8")

    actions_path = data / "RecoveryActions.json"
    actions = json.loads(actions_path.read_text(encoding="utf-8"))
    actions["actions"].append({
        "id": "R-OPEN-PASSWORD-MANAGER", "name": "Open the password manager", "description": "Reach the device it runs on and unlock it with the master password.",
        "purpose": "access", "type": "composite", "params": [{"name": "manager", "class": "PasswordManager"}], "combinator": "all_of",
        "requires": [{"type": "reach", "target": "$manager"}, {"type": "intact", "target": "$manager"}],
        "steps": [{"action": "R-OBTAIN-SECRET", "args": {"secret": "$manager.master_password"}, "when": "$manager.master_password", "guards": "$manager"}],
    })
    obtain = next(a for a in actions["actions"] if a["id"] == "R-OBTAIN-SECRET")
    obtain["steps"].append({"action": "R-OPEN-PASSWORD-MANAGER", "args": {"manager": "$manager"}, "foreach": {"over": "$secret.password_managers", "as": "manager"}})
    actions_path.write_text(json.dumps(actions, indent=2), encoding="utf-8")

    threats_path = data / "Threats.json"
    threats = json.loads(threats_path.read_text(encoding="utf-8"))
    threats["threats"].append({
        "id": "T-PWM-BREACH", "name": "Password manager breached", "description": "The vault file is copied from the device or the cloud sync.",
        "origin": "added", "target": {"class": "PasswordManager"}, "category": "software", "source": ["outsider"], "phases": ["storage", "use"],
        "impacts": [{"on": "self", "kind": "disclosed"}], "likelihood": 2,
    })
    threats_path.write_text(json.dumps(threats, indent=2), encoding="utf-8")

    texts_path = data / "Texts.json"
    texts = json.loads(texts_path.read_text(encoding="utf-8"))
    texts["classes"]["PasswordManager"] = ["Password manager", "Password managers"]
    texts_path.write_text(json.dumps(texts, indent=2), encoding="utf-8")


def extended_setup():
    data = json.loads((HERE / "TestSetup.json").read_text(encoding="utf-8"))
    data["pins"].append({"id": "pin-master", "name": "Master password"})
    next(b for b in data["backups"] if b["id"] == "bk-head")["items"].append({"subject": {"pin": "pin-master"}, "format": "text"})
    data["password_managers"] = [{"id": "pwm", "name": "Password manager", "runs_on": "laptop2", "master_password": "pin-master", "stores": ["pin5"]}]
    return data


class Extensibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        root = Path(cls.tmp) / "root"
        root.mkdir()
        shutil.copy(ROOT / "SetupOntology.schema.json", root / "SetupOntology.schema.json")
        (root / "GenericThreatModelling").mkdir()
        for p in (ROOT / "GenericThreatModelling").glob("*.json"):
            shutil.copy(p, root / "GenericThreatModelling" / p.name)
        shutil.copytree(ROOT / "Lookups", root / "Lookups")
        extend_knowledge(root)
        setup = Path(cls.tmp) / "setup.json"
        setup.write_text(json.dumps(extended_setup()), encoding="utf-8")
        out = Path(cls.tmp) / "setup.analysis.json"
        html = Path(cls.tmp) / "setup.report.html"
        env = dict(os.environ, CUSTODY_DATA_ROOT=str(root))
        cls.proc = subprocess.run([sys.executable, str(CLI), str(setup), "-o", str(out), "--html", str(html)], capture_output=True, text=True, env=env)
        cls.result = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        cls.html = html.read_text(encoding="utf-8") if html.exists() else ""

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rows(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        return {r["id"]: r for r in self.result["rows"]}

    def test_the_new_class_is_analysed_without_any_engine_change(self):
        rows = self.rows()
        self.assertIn("T-PWM-BREACH@pwm", rows)
        self.assertEqual(rows["T-PWM-BREACH@pwm"]["class"], "PasswordManager")
        self.assertIn("pwm", set(rows["T-PWM-BREACH@pwm"]["effects"]["disclosed"]))

    def test_the_new_carrier_takes_part_in_the_access_model(self):
        rows = self.rows()
        breach = rows["T-PWM-BREACH@pwm"]
        self.assertNotIn("pin5", set(breach["effects"].get("known", [])), "the master password in Alice's head still guards the vault")
        malware = rows["T-DEV-MALWARE@laptop2"]
        self.assertIn("pwm", set(malware["effects"]["controlled"]), "software inherits what happens to its host")
        self.assertIn("pin5", set(malware["effects"]["known"]), "malware on the host reads the vault despite the master password")
        coercion = rows["T-PERSON-COERCION@alice"]
        self.assertIn("pin5", set(coercion["effects"]["known"]), "Alice carries the laptop and knows the master password")

    def test_the_new_entity_is_a_dependency_and_appears_in_the_report(self):
        rows = self.rows()
        self.assertIn("w-pin", {o["wallet"] for o in rows["T-PWM-BREACH@pwm"]["outcomes"]}, "the wallet whose PIN the vault keeps depends on it")
        self.assertIn('"PasswordManager"', self.html)
        self.assertIn("T-PWM-BREACH@pwm", self.html)


if __name__ == "__main__":
    unittest.main()
