import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/"converters"))
import startupads as c
import startupads_support as s

class StartupAdsTests(unittest.TestCase):
    def test_adapters(self):
        rail="placementNo 0007 G0054 $request.body $done"
        flight="10000012 1000019 rpid HTTP/1.1 404 $done"
        self.assertEqual(s.adapt_and_test("rail_echo",rail,"request")[1],6)
        self.assertEqual(s.adapt_and_test("flight_header",flight,"request")[1],6)
        self.assertEqual(s.adapt_and_test("flight_header",flight,"response")[1],6)
        with self.assertRaises(ValueError):s.adapt_and_test("rail_echo",rail,"response")
        with self.assertRaises(ValueError):s.adapt_and_test("rail_echo","unexpected","request")

    def test_binary_adapter(self):
        from startupads_baidu_test import test_baidu
        self.assertEqual(test_baidu()[1],11)

    def test_pin(self):
        with patch.object(c,"github_revision",return_value="a"*40):
            self.assertEqual(c.pin_url("https://raw.githubusercontent.com/a/b/refs/heads/master/f.js"),"https://raw.githubusercontent.com/a/b/"+"a"*40+"/f.js")
            self.assertEqual(c.pin_url("https://raw.githubusercontent.com/a/b/main/js/f.js"),"https://raw.githubusercontent.com/a/b/"+"a"*40+"/js/f.js")
        for url in ("https://other.test/a/b/main/f.js","https://raw.githubusercontent.com/a/b/main/f.js?secret=x","http://raw.githubusercontent.com/a/b/main/f.js"):
            with self.assertRaises(ValueError):c.pin_url(url)

    def test_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            (root/"plugins").mkdir()
            for name in ("TxvideoAD.lpx","MT.lpx","helloobike.lpx"):
                (root/"plugins"/name).write_text("[Rewrite]\n^https://a\\.test/ad reject-200\n[MITM]\nhostname = a.test\n")
            r=[(1,"request",r"^https:\/\/a\.test/ad","reject",""),(2,"request",r"^https://a\.test/ad","reject-200","")]
            findings=s.audit_conflicts(r,[],["a.test"],root)
            self.assertTrue(any(x["kind"]=="internal_exact" and x["blocking"] for x in findings))
            self.assertTrue(any(x["kind"]=="existing_exact" and x["blocking"] for x in findings))
            self.assertTrue(any(x["kind"]=="shared_mitm" and not x["blocking"] for x in findings))

    def test_conversion_fails_closed(self):
        source="\n".join([r"^https://example\.test/ad url reject-200",r"^https://example\.test/x url response-body foo response-body bar",r"^https://example\.test/j url jsonjq-response-body 'del(.ads)'","host, example.test, direct","hostname = example.test","unrecognized"])
        with contextlib.redirect_stdout(io.StringIO()):
            rw,sc,hosts,filters,issues,urls=c.convert(source)
        self.assertEqual(len(rw),3)
        self.assertEqual(filters,["DOMAIN,example.test,DIRECT"])
        self.assertTrue(any("unrecognized" in x["reason"] for x in issues))
        self.assertTrue(any("baseline" in x["reason"] for x in issues))
        self.assertIn("response.body.replace",rw[1])
        self.assertIn("response.json.jq",rw[2])

    def test_publication_guard_before_network_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            source=root/"fake.conf"
            source.write_text("dummy")
            with patch.object(sys,"argv",["startupads.py","--publish","--source-file",str(source)]),patch.object(c,"download",side_effect=AssertionError("network forbidden")):
                with self.assertRaises(SystemExit):c.main()
            self.assertEqual(list(root.iterdir()),[source])

if __name__=="__main__": unittest.main(verbosity=2)
