import unittest
from nightrecon_red_engine.web_har_import import HarEvidence,WebRequestSummary
from nightrecon_red_engine.web_har_analysis import compare_har
class TestHarComparison(unittest.TestCase):
    def test_scope_and_differences(self):
        old=HarEvidence("old",(WebRequestSummary("https://example.org","GET",200),))
        new=HarEvidence("new",(WebRequestSummary("https://example.org","GET",403),))
        self.assertEqual(compare_har(old,new,frozenset()),())
        result=compare_har(old,new,frozenset({"https://example.org"}))
        self.assertEqual((result[0].previous_statuses,result[0].current_statuses),((200,),(403,)))
    def test_no_change(self):
        one=HarEvidence("test",(WebRequestSummary("https://example.org","GET",200),))
        self.assertEqual(compare_har(one,one,frozenset({"https://example.org"})),())
