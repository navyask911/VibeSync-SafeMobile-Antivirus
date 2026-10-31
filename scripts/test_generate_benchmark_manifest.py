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
