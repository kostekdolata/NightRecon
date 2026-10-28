import unittest
from nightrecon_red_engine.nmap_import import NmapEvidence,ImportedHost,ImportedService
from nightrecon_red_engine.nmap_scan_analysis import compare_nmap_scans
class TestNmapComparison(unittest.TestCase):
    def test_scope_and_changes(self):
        old=NmapEvidence("nmap",(ImportedHost("192.0.2.1","up",(ImportedService("tcp",80,"open","http","",""),)),))
        new=NmapEvidence("nmap",(ImportedHost("192.0.2.1","up",(ImportedService("tcp",80,"closed","http","",""),)),))
        self.assertEqual(compare_nmap_scans(old,new,frozenset()),())
        result=compare_nmap_scans(old,new,frozenset({"192.0.2.1"}))
        self.assertEqual((result[0].before,result[0].after),("open","closed"))
