"""Windows Job Object containment for trusted local diagnostic processes.

Requires Windows. Assign immediately after launch; a small pre-assignment
window remains until a suspended-process launcher is implemented.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes
import os

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
DEFAULT_JOB_MEMORY_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_PROCESSES = 16
JobObjectExtendedLimitInformation = 9

class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_=[("PerProcessUserTimeLimit",ctypes.c_int64),
      ("PerJobUserTimeLimit",ctypes.c_int64),
      ("LimitFlags",wintypes.DWORD),("MinimumWorkingSetSize",ctypes.c_size_t),
      ("MaximumWorkingSetSize",ctypes.c_size_t),
      ("ActiveProcessLimit",wintypes.DWORD),
      ("Affinity",ctypes.c_size_t),("PriorityClass",wintypes.DWORD),
      ("SchedulingClass",wintypes.DWORD)]

class IO_COUNTERS(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint64) for name in (
        "ReadOperationCount","WriteOperationCount","OtherOperationCount",
        "ReadTransferCount","WriteTransferCount","OtherTransferCount")]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_=[("BasicLimitInformation",JOBOBJECT_BASIC_LIMIT_INFORMATION),
      ("IoInfo",IO_COUNTERS),("ProcessMemoryLimit",ctypes.c_size_t),
      ("JobMemoryLimit",ctypes.c_size_t),
      ("PeakProcessMemoryUsed",ctypes.c_size_t),
      ("PeakJobMemoryUsed",ctypes.c_size_t)]

class WindowsJob:
    def __init__(self, process):
        if os.name!="nt":
            raise RuntimeError("Windows Job Objects only exist on Windows")
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype=wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        kernel.SetInformationJobObject.restype=wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype=wintypes.BOOL
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        kernel.CloseHandle.restype=wintypes.BOOL
        self._kernel=kernel
        self._handle=kernel.CreateJobObjectW(None,None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info=JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags=(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY |
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            )
            info.BasicLimitInformation.ActiveProcessLimit=DEFAULT_MAX_PROCESSES
            info.JobMemoryLimit=DEFAULT_JOB_MEMORY_BYTES
            if not kernel.SetInformationJobObject(
                self._handle,JobObjectExtendedLimitInformation,
                ctypes.byref(info),ctypes.sizeof(info)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.AssignProcessToJobObject(self._handle,wintypes.HANDLE(int(process._handle))):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def close(self):
        if getattr(self,"_handle",None):
            self._kernel.CloseHandle(self._handle)
            self._handle=None

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()
