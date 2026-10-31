"""Offline regression tests for recent discovery and MalwareBazaar JSON responses."""
import io,json,unittest,urllib.error
from unittest.mock import patch
import generate_benchmark_manifest as m
from benchmark_apk_validation import InvalidAndroidAPK

class Response:
    def __init__(self,raw,mime="application/json"):
        self.status=200;self.headers={"Content-Type":mime};self.raw=raw
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self,n):return self.raw[:n]

class Tests(unittest.TestCase):
    key="test-credential-012345"
    def row(self,i,kind="apk"):
        return {"sha256_hash":f"{i:064x}","file_type":kind,"file_name":f"sample.{kind}"}
    def test_recent_request_once_auth_key(self):
        raw=json.dumps({"query_status":"ok","data":[self.row(i) for i in range(320)]}).encode()
        with patch("urllib.request.urlopen",return_value=Response(raw)) as mock:
            result=m.post_api({"query":"recent_detections","hours":"168"},self.key)
        self.assertEqual(len(result["data"]),320)
        mock.assert_called_once()
        req=mock.call_args.args[0]
        self.assertEqual(dict((k.lower(),v) for k,v in req.header_items())["auth-key"],self.key)
        self.assertEqual(req.data,b"query=recent_detections&hours=168")
    def test_up_to_300_unique_android_hashes(self):
        rows=[self.row(i) for i in range(320)]+[self.row(0),self.row(1000,"exe")]
        result=m.parse_recent_candidates({"query_status":"ok","data":rows})
        self.assertEqual(len(result),300)
        self.assertEqual(len(set(r["sha256"] for r in result)),300)
    def test_skip_not_found_and_bad_apk(self):
        seen=[]
        def verify(row):
            seen.append(row["sha256"])
            if len(seen)==1:raise m.SampleUnavailable('{"query_status":"file_not_found"}')
            if len(seen)==2:raise InvalidAndroidAPK("missing AndroidManifest.xml")
        with patch("sys.stderr"):
            result=m.manifest_from_recent({"query_status":"ok","data":[self.row(i) for i in range(130)]},verify)
        self.assertEqual(result["verified_apk_count"],100)
        self.assertEqual(result["rejected_candidate_count"],2)
        self.assertEqual(len(seen),102)
    def test_insufficient_recent_apks_cannot_publish(self):
        with self.assertRaisesRegex(m.DatasetUnavailable,"Only 20/100"):
            m.manifest_from_recent({"query_status":"ok","data":[self.row(i) for i in range(20)]},lambda _:None)
    def test_json_file_not_found_detected_even_as_octet_stream(self):
        for mime in ("application/json","application/octet-stream"):
            with patch("urllib.request.urlopen",return_value=Response(b'{"query_status":"file_not_found"}',mime)):
                with self.assertRaisesRegex(m.SampleUnavailable,"file_not_found"):
                    m.post_api({"query":"get_file","sha256_hash":"a"*64},self.key)
    def test_http_403_and_429_fail_globally(self):
        for status in (403,429):
            err=urllib.error.HTTPError(m.API,status,"err",{"Content-Type":"application/json"},
                                      io.BytesIO(b'{"query_status":"rate_limit"}'))
            with patch("urllib.request.urlopen",side_effect=err):
                with self.assertRaisesRegex(m.DatasetUnavailable,"rate_limit"):
                    m.post_api({"query":"get_file","sha256_hash":"a"*64},self.key)
    def test_auth_header_for_zip_download(self):
        with patch("urllib.request.urlopen",return_value=Response(b"PK\x03\x04body","application/zip")) as mock:
            self.assertEqual(m.post_api({"query":"get_file","sha256_hash":"a"*64},self.key),b"PK\x03\x04body")
        self.assertEqual(dict((k.lower(),v) for k,v in mock.call_args.args[0].header_items())["auth-key"],self.key)
    def test_429_never_skipped(self):
        seen=[]
        def verify(row):
            seen.append(row)
            raise m.DatasetUnavailable("HTTP 429 quota")
        with self.assertRaisesRegex(m.DatasetUnavailable,"429"):
            m.manifest_from_recent({"query_status":"ok","data":[self.row(i) for i in range(130)]},verify)
        self.assertEqual(len(seen),1)
    def test_bulk_discovery_rejected(self):
        with patch("urllib.request.urlopen") as mock:
            with self.assertRaisesRegex(m.DatasetUnavailable,"Historical/bulk"):
                m.post_api({"query":"get_file_type","file_type":"apk"},self.key)
            mock.assert_not_called()

if __name__=="__main__":unittest.main()
