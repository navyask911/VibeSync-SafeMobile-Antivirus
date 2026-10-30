"""Harmless offline fixtures for the benchmark's fail-closed reporting rules."""
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import industry_benchmark as bench

class IndustryBenchmarkTests(unittest.TestCase):
    def test_unapproved_malware_manifest_fails_without_network(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "owner-approved"):
                bench.prepare(types.SimpleNamespace(plan=Path(tmp)/"plan.json"))

    def test_missing_device_scans_cannot_generate_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            bench.save(root/"plan.json",{"samples":[{"sample_id":"b0000","label":"benign","sha256":"0"*64}]})
            (root/"results").mkdir()
            a=types.SimpleNamespace(plan=root/"plan.json",results=root/"results",
                output_json=root/"metrics.json",output_markdown=root/"report.md")
            with self.assertRaisesRegex(ValueError,"incomplete"):
                bench.summarize(a)
            self.assertFalse(a.output_json.exists())

    def test_synthetic_fixture_math_not_a_published_benchmark(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);results=root/"results";results.mkdir()
            source=[];out=[]
            for label,prefix in (("benign","b"),("malicious","m")):
                for i in range(1000):
                    sid=prefix+("%04d"%i);sha=("%064x"%(i+1+(1000 if prefix=="m" else 0)))
                    source.append({"sample_id":sid,"label":label,"sha256":sha})
                    verdict=("THREAT" if (label=="malicious" and i<10) or (label=="benign" and i<5) else "NO_MATCH")
                    out.append(dict(sample_id=sid,label=label,sha256=sha,verdict=verdict,duration_ms=7,ml_scored=False))
            bench.save(root/"plan.json",dict(samples=source,provenance={"commit":"synthetic-unit-test-only"}))
            bench.save(results/"batch-0.json",dict(samples=out))
            a=types.SimpleNamespace(plan=root/"plan.json",results=results,
                output_json=root/"metrics.json",output_markdown=root/"report.md")
            bench.summarize(a)
            result=json.loads(a.output_json.read_text())
            self.assertEqual(result["tpr_percent"],1.0)
            self.assertEqual(result["fpr_percent"],0.5)
            self.assertEqual(result["mean_latency_ms"],7.0)
            self.assertEqual(result["ml_samples_scored"],0)
            # Temp fixtures are intentionally never committed or published.
            self.assertIn("MEASURED",a.output_markdown.read_text())

if __name__=="__main__":
    unittest.main()
