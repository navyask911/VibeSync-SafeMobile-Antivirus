"""Mock-only MalwareBazaar selection tests; no live network or sample bytes."""
import unittest
from unittest.mock import patch
import generate_benchmark_manifest as m

class ManifestTests(unittest.TestCase):
    def test_select_exactly_100(self):
        rows=[{"sha256_hash":f"{i:064x}","file_type":"apk","file_name":"sample.apk"} for i in range(120)]
        rows.append(rows[0])
        rows.append({"sha256_hash":"f"*64,"file_type":"exe","file_name":"sample.exe"})
        x=m.manifest_from_response({"query_status":"ok","data":rows})
        self.assertEqual(len(x["samples"]),100)
        self.assertEqual(len({t["sha256"] for t in x["samples"]}),100)

    def test_byte_level_preflight_replaces_invalid_sample_before_pinning(self):
        rows=[{"sha256_hash":f"{i:064x}","file_type":"apk","file_name":"payload.apk"} for i in range(110)]
        first=m.manifest_from_response({"query_status":"ok","data":rows})
        reject={x["sha256"] for x in first["samples"][:2]}
        def validate(candidate):
            if candidate["sha256"] in reject:
                raise m.InvalidAndroidAPK("not an Android APK")
        with patch("sys.stderr"):
            actual=m.manifest_from_response({"query_status":"ok","data":rows},validator=validate)
        self.assertEqual(actual["verified_apk_count"],100)
        self.assertEqual(actual["rejected_candidate_count"],2)
        self.assertEqual(len(actual["samples"]),100)
        self.assertTrue(reject.isdisjoint({x["sha256"] for x in actual["samples"]}))

    def test_apk_magic_and_compiled_manifest_validation(self):
        import hashlib,io,zipfile
        from benchmark_apk_validation import validate_apk_bytes,InvalidAndroidAPK
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as z:
            z.writestr("AndroidManifest.xml",b"\x03\x00\x08\x00"+b"\x00"*8)
        raw=stream.getvalue()
        self.assertEqual(raw,validate_apk_bytes(raw,hashlib.sha256(raw).hexdigest()))
        for bad in (b"MZ"+"x".encode(), b"\x7fELF"+"x".encode(), b"dex\n035\x00"):
            with self.assertRaises(InvalidAndroidAPK):
                validate_apk_bytes(bad,hashlib.sha256(bad).hexdigest())
        invalid=io.BytesIO()
        with zipfile.ZipFile(invalid,"w") as z: z.writestr("readme.txt","not Android")
        blob=invalid.getvalue()
        with self.assertRaises(InvalidAndroidAPK):
            validate_apk_bytes(blob,hashlib.sha256(blob).hexdigest())

    def test_no_partial_manifest_on_exhausted_validated_supply(self):
        rows=[{"sha256_hash":f"{i:064x}","file_type":"apk","file_name":"payload.apk"} for i in range(105)]
        def reject(candidate):
            if int(candidate["sha256"],16)<30:
                raise m.InvalidAndroidAPK("non-APK")
        with patch("sys.stderr"):
            with self.assertRaisesRegex(m.DatasetUnavailable,"no incomplete report"):
                m.manifest_from_response({"query_status":"ok","data":rows},validator=reject)

    def test_rate_limit_status_fails_closed(self):
        with self.assertRaisesRegex(m.DatasetUnavailable,"rate_limit"):
            m.manifest_from_response({"query_status":"rate_limit","data":[]})
    def test_no_candidates_fails_closed(self):
        with self.assertRaisesRegex(m.DatasetUnavailable,"Only 0"):
            m.manifest_from_response({"query_status":"ok","data":[]})
    def test_missing_key_no_network(self):
        with patch("urllib.request.urlopen") as call:
            with self.assertRaisesRegex(m.DatasetUnavailable,"missing"):
                m.post_api({"query":"get_file_type"},"")
            call.assert_not_called()

if __name__=="__main__":unittest.main()
