"""Offline tests: no live MalwareBazaar or GitHub network requests."""
import hashlib
import unittest
from unittest.mock import patch

import generate_benchmark_manifest as m
from benchmark_apk_validation import InvalidAndroidAPK


class StaticManifestTests(unittest.TestCase):
    def example_list(self, extra=0):
        values=[f"{i:064x}" for i in range(300+extra)]
        return ("\n".join(values)+"\n").encode("utf8")

    def test_first_300_deduplicated(self):
        values=["0"*64,"0"*64]+[f"{i:064x}" for i in range(1,301)]
        selected=m.parse_static_hash_list(("\n".join(values)).encode("utf8"))
        self.assertEqual(len(selected),300)
        self.assertEqual(len(set(selected)),300)
        self.assertEqual(selected[0],"0"*64)
        self.assertEqual(selected[-1],f"{299:064x}")

    def test_missing_source_fails_closed(self):
        with self.assertRaisesRegex(m.DatasetUnavailable,"only 3"):
            m.parse_static_hash_list(b"0"*64+b"\n"+b"1"*64+b"\n"+b"2"*64+b"\n")

    def test_invalid_or_non_hash_cannot_enter_plan(self):
        with self.assertRaisesRegex(m.DatasetUnavailable,"Malformed"):
            m.parse_static_hash_list(b"hello world\n"+self.example_list())
        with self.assertRaisesRegex(m.DatasetUnavailable,"300"):
            m.manifest_from_static_hashes(["0"*64]*300,lambda sha:None,"a"*64)

    def test_fresh_manifest_refills_after_bad_apks(self):
        hashes=m.parse_static_hash_list(self.example_list())
        observed=[]
        def verifier(sha):
            observed.append(sha)
            if len(observed) in (1,5,8):
                raise InvalidAndroidAPK("bad APK")
        with patch("sys.stderr"):
            output=m.manifest_from_static_hashes(hashes,verifier,"b"*64)
        self.assertEqual(len(output["samples"]),100)
        self.assertEqual(output["rejected_candidate_count"],3)
        self.assertEqual(output["candidate_limit"],300)
        self.assertEqual(len(observed),103)
        self.assertEqual(output["samples"][-1]["sha256"],hashes[102])

    def test_rate_limit_is_global_and_ends_run(self):
        hashes=m.parse_static_hash_list(self.example_list())
        def verifier(sha):
            raise m.DatasetUnavailable("MalwareBazaar HTTP 429 rate limit; stop this run")
        with self.assertRaisesRegex(m.DatasetUnavailable,"429"):
            m.manifest_from_static_hashes(hashes,verifier,"b"*64)

    def test_all_unavailable_fail_closed(self):
        hashes=m.parse_static_hash_list(self.example_list())
        def verifier(sha):
            raise InvalidAndroidAPK("non Android")
        with patch("sys.stderr"):
            with self.assertRaisesRegex(m.DatasetUnavailable,"Only 0 valid APKs"):
                m.manifest_from_static_hashes(hashes,verifier,"b"*64)

    def test_reject_bulk_api_discovery_without_network(self):
        with patch("urllib.request.urlopen") as network:
            with self.assertRaisesRegex(m.DatasetUnavailable,"Only individual get_file"):
                m.post_api({"query":"get_file_type","file_type":"apk","limit":"1000"},"token1234567")
            network.assert_not_called()

    def test_pinned_source_exact_url_only(self):
        with patch("urllib.request.urlopen") as network:
            with self.assertRaisesRegex(m.DatasetUnavailable,"Unapproved"):
                m.get_static_hashes_once("https://example.com/untrusted.txt")
            network.assert_not_called()

    def test_static_list_download_once_mocked(self):
        class Response:
            status=200
            url=m.STATIC_LIST_URL
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,count):return b"0"*64+b"\n"
        with patch("urllib.request.urlopen",return_value=Response()) as network:
            self.assertEqual(m.get_static_hashes_once(),b"0"*64+b"\n")
            network.assert_called_once()


if __name__=="__main__":
    unittest.main()
