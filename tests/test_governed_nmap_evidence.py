import unittest
from nightrecon_red_engine.governed_command_runner import CommandOutcome
from nightrecon_red_engine.governed_nmap_evidence import parse_governed_nmap_result
def xml(host="192.0.2.4",port=80):
    return f'<nmaprun><host><status state="up"/><address addr="{host}" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state state="open"/></port></ports></host></nmaprun>'
class TestGovernedNmapEvidence(unittest.TestCase):
    def test_expected_host_and_port(self):
        observed=parse_governed_nmap_result(outcome=CommandOutcome("nmap-bounded-connect",0,xml(),""),
                                            target="192.0.2.4")
        self.assertEqual(observed.hosts[0].services[0].port,80)
    def test_reject_other_host(self):
        with self.assertRaises(PermissionError):
            parse_governed_nmap_result(outcome=CommandOutcome("nmap-bounded-connect",0,xml("198.51.100.1"),""),
                                       target="192.0.2.4")
    def test_reject_other_port(self):
        with self.assertRaises(PermissionError):
            parse_governed_nmap_result(outcome=CommandOutcome("nmap-bounded-connect",0,xml(port=445),""),
                                       target="192.0.2.4")
    def test_failed_command_not_evidence(self):
        with self.assertRaises(ValueError):
            parse_governed_nmap_result(outcome=CommandOutcome("nmap-bounded-connect",1,xml(),""),
                                       target="192.0.2.4")
