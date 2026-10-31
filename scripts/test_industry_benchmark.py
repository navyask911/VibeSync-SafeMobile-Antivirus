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
            with self.assertRaisesRegex(ValueError, "No MalwareBazaar"):
                bench.prepare(types.SimpleNamespace(plan=Path(tmp)/"plan.json", malware_manifest=Path(tmp)/"missing.json"))

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
                for i in range(100):
                    sid=prefix+("%04d"%i);sha=("%064x"%(i+1+(100 if prefix=="m" else 0)))
                    source.append({"sample_id":sid,"label":label,"sha256":sha})
                    verdict=("THREAT" if (label=="malicious" and i<10) or (label=="benign" and i<5) else "NO_MATCH")
                    out.append(dict(sample_id=sid,label=label,sha256=sha,verdict=verdict,duration_ms=7,ml_scored=False))
            bench.save(root/"plan.json",dict(samples=source,provenance={"commit":"synthetic-unit-test-only"}))
            bench.save(results/"batch-0.json",dict(samples=out))
            a=types.SimpleNamespace(plan=root/"plan.json",results=results,
                output_json=root/"metrics.json",output_markdown=root/"report.md")
            bench.summarize(a)
            result=json.loads(a.output_json.read_text())
            self.assertEqual(result["tpr_percent"],10.0)
            self.assertEqual(result["fpr_percent"],5.0)
            self.assertEqual(result["mean_latency_ms"],7.0)
            self.assertEqual(result["ml_samples_scored"],0)
            # Temp fixtures are intentionally never committed or published.
            self.assertIn("MEASURED",a.output_markdown.read_text())


    def test_ten_matrix_shards_partition_each_label_exactly_once(self):
        samples=[]
        for prefix,label in (("b","benign"),("m","malicious")):
            samples.extend(dict(sample_id=f"{prefix}{i:04d}",label=label,
                sha256=f"{i+(100 if prefix=='m' else 0):064x}")
                for i in range(100))
        plan={"samples":samples}
        seen=set()
        for shard in range(10):
            for label in ("benign","malicious"):
                chosen=bench.shard_samples(plan,shard,label)
                self.assertEqual(len(chosen),10)
                self.assertFalse(set(x["sample_id"] for x in chosen)&seen)
                seen.update(x["sample_id"] for x in chosen)
        self.assertEqual(seen,set(x["sample_id"] for x in samples))
        with self.assertRaisesRegex(ValueError,"0..9"):
            bench.shard_samples(plan,10,"benign")

    def test_merge_requires_all_ten_correct_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);shards=root/"shards";shards.mkdir()
            plan=[]
            for prefix,label in (("b","benign"),("m","malicious")):
                plan.extend(dict(sample_id=f"{prefix}{i:04d}",label=label,
                    sha256=f"{i+(100 if prefix=='m' else 0):064x}")
                    for i in range(100))
            bench.save(root/"plan.json",{"samples":plan,"provenance":{"commit":"synthetic-tests"}})
            params=types.SimpleNamespace(shards=shards,plan=root/"plan.json",results=root/"results",run_id="12345")
            with self.assertRaisesRegex(ValueError,"ten shard"):
                bench.merge(params)
            for shard in range(10):
                part=shards/f"industry-benchmark-shard-{shard}-12345";part.mkdir()
                for label in ("benign","malicious"):
                    selected=bench.shard_samples({"samples":plan},shard,label)
                    rows=[dict(**s,verdict="NO_MATCH",duration_ms=3) for s in selected]
                    bench.save(part/f"batch-{label}.json",{"samples":rows})
            bench.merge(params)
            self.assertEqual(len(list(params.results.glob("batch-*.json"))),20)
            a=types.SimpleNamespace(plan=params.plan,results=params.results,
                output_json=root/"metrics.json",output_markdown=root/"report.md")
            bench.summarize(a)
            metrics=json.loads(a.output_json.read_text())
            self.assertEqual(metrics["status"],"MEASURED")
            self.assertEqual(metrics["total_apps"],200)
            self.assertEqual(metrics["mean_latency_ms"],3.0)
            # Duplicate/missing artifacts must never publish a report.
            (shards/"industry-benchmark-shard-9-12345"/"batch-malicious.json").unlink()
            empty=root/"results2"
            with self.assertRaisesRegex(ValueError,"missing/extra"):
                bench.merge(types.SimpleNamespace(shards=shards,plan=params.plan,
                    results=empty,run_id="12345"))

if __name__=="__main__":
    unittest.main()
