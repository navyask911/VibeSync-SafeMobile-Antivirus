"""Offline-only fixtures: hash corpus and runner-scratch verification."""
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import generate_benchmark_manifest as corpus


def fake_apk(marker):
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w") as z:
        z.writestr("AndroidManifest.xml",b"\x03\x00\x08\x00"+b"\x00"*12)
        z.writestr("assets/number.txt",str(marker))
    return out.getvalue()


class CorpusTests(unittest.TestCase):
    def case(self):
        apk=[fake_apk(i) for i in range(500)]
        hashes=[hashlib.sha256(x).hexdigest() for x in apk]
        return hashes,apk

    def test_500_sha_only_manifest(self):
        hashes,_=self.case()
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/"hashes.txt"
            p.write_text("\n".join(hashes)+"\n")
            self.assertEqual(corpus.read_hashes(p),hashes)
            p.write_text("\n".join(hashes[:-1])+"\n")
            with self.assertRaisesRegex(corpus.DatasetUnavailable,"500"):
                corpus.read_hashes(p)

    def test_100_verified_with_replacements_and_ephemeral_files(self):
        hashes,apks=self.case()
        counter=[]
        def fetch(sha):
            counter.append(sha)
            if len(counter) in (1,4):
                raise corpus.InvalidSample("file not found")
            return apks[len(counter)-1]
        with tempfile.TemporaryDirectory() as t,patch("sys.stderr"):
            result=corpus.select_verified(hashes,Path(t),fetch)
            self.assertEqual(result["verified_apk_count"],100)
            self.assertEqual(len(result["samples"]),100)
            self.assertEqual(len(counter),102)
            self.assertEqual(len(list(Path(t).glob("*.apk"))),100)

    def test_no_measurement_if_insufficient_verified_apks(self):
        hashes,_=self.case()
        with tempfile.TemporaryDirectory() as t,patch("sys.stderr"):
            with self.assertRaisesRegex(corpus.DatasetUnavailable,"Only 0"):
                corpus.select_verified(hashes,Path(t),lambda sha: (_ for _ in ()).throw(corpus.InvalidSample("unavailable")))

    def test_no_unpinned_source_path(self):
        with self.assertRaises(corpus.DatasetUnavailable):
            corpus.sample_url("../bad")

if __name__=="__main__":unittest.main()
