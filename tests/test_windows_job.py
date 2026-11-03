import os
import subprocess
import sys
import unittest
from nightrecon_red_engine.windows_job import WindowsJob

class TestWindowsJob(unittest.TestCase):
    @unittest.skipUnless(os.name=="nt","Windows only")
    def test_assign_local_child_and_cleanup(self):
        p=subprocess.Popen([sys.executable,"-c","print('ok')"],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        with WindowsJob(p):
            out,err=p.communicate(timeout=5)
        self.assertEqual(p.returncode,0)
        self.assertEqual(out.strip(),b"ok")

    @unittest.skipIf(os.name=="nt","Non-Windows only")
    def test_not_supported_elsewhere(self):
        with self.assertRaises(RuntimeError):
            WindowsJob(None)
