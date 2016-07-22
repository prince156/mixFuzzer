# generated by 'xml2py'

#
# $Id: windows_h.py 194 2007-04-05 15:31:53Z cameron $
#


# flags 'windows.xml -s DEBUG_EVENT -s CONTEXT -s MEMORY_BASIC_INFORMATION -s LDT_ENTRY -s PROCESS_INFORMATION -s STARTUPINFO -s SYSTEM_INFO -s TOKEN_PRIVILEGES -s LUID -s HANDLE -o windows_h.py'

# PEDRAM - line swap ... have to patch in our own __reduce__ definition to each ctype.
#from ctypes import *
from my_ctypes import *

# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 4188
class _TOKEN_PRIVILEGES(Structure):
    pass
TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 3774
class _STARTUPINFOA(Structure):
    pass
STARTUPINFOA = _STARTUPINFOA
STARTUPINFO = STARTUPINFOA
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1661
class _LDT_ENTRY(Structure):
    pass
LDT_ENTRY = _LDT_ENTRY
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 4534
class _MEMORY_BASIC_INFORMATION(Structure):
    pass
MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 697
class _DEBUG_EVENT(Structure):
    pass
DEBUG_EVENT = _DEBUG_EVENT
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1563
class _CONTEXT(Structure):
    pass
CONTEXT = _CONTEXT
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 497
class _SYSTEM_INFO(Structure):
    pass
SYSTEM_INFO = _SYSTEM_INFO
HANDLE = c_void_p
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 229
class _PROCESS_INFORMATION(Structure):
    pass
PROCESS_INFORMATION = _PROCESS_INFORMATION
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 394
class _LUID(Structure):
    pass
LUID = _LUID
WORD = c_ushort
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1664
class N10_LDT_ENTRY3DOLLAR_4E(Union):
    pass
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1665
class N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E(Structure):
    pass
BYTE = c_ubyte
N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1665
    ('BaseMid', BYTE),
    ('Flags1', BYTE),
    ('Flags2', BYTE),
    ('BaseHi', BYTE),
]
assert sizeof(N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E) == 4, sizeof(N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E)
assert alignment(N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E) == 1, alignment(N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E)
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1671
class N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E(Structure):
    pass
DWORD = c_ulong
N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1671
    ('BaseMid', DWORD, 8),
    ('Type', DWORD, 5),
    ('Dpl', DWORD, 2),
    ('Pres', DWORD, 1),
    ('LimitHi', DWORD, 4),
    ('Sys', DWORD, 1),
    ('Reserved_0', DWORD, 1),
    ('Default_Big', DWORD, 1),
    ('Granularity', DWORD, 1),
    ('BaseHi', DWORD, 8),
]
#assert sizeof(N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E) == 4, sizeof(N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E)
#assert alignment(N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E) == 4, alignment(N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E)
N10_LDT_ENTRY3DOLLAR_4E._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1664
    ('Bytes', N10_LDT_ENTRY3DOLLAR_43DOLLAR_5E),
    ('Bits', N10_LDT_ENTRY3DOLLAR_43DOLLAR_6E),
]
#assert sizeof(N10_LDT_ENTRY3DOLLAR_4E) == 4, sizeof(N10_LDT_ENTRY3DOLLAR_4E)
#assert alignment(N10_LDT_ENTRY3DOLLAR_4E) == 4, alignment(N10_LDT_ENTRY3DOLLAR_4E)
_LDT_ENTRY._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1661
    ('LimitLow', WORD),
    ('BaseLow', WORD),
    ('HighWord', N10_LDT_ENTRY3DOLLAR_4E),
]
#assert sizeof(_LDT_ENTRY) == 8, sizeof(_LDT_ENTRY)
#assert alignment(_LDT_ENTRY) == 4, alignment(_LDT_ENTRY)
PVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = UINT_PTR
_MEMORY_BASIC_INFORMATION._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 4534
    ('BaseAddress', PVOID),
    ('AllocationBase', PVOID),
    ('AllocationProtect', DWORD),
    ('RegionSize', SIZE_T),
    ('State', DWORD),
    ('Protect', DWORD),
    ('Type', DWORD),
]
#assert sizeof(_MEMORY_BASIC_INFORMATION) == 28, sizeof(_MEMORY_BASIC_INFORMATION)
#assert alignment(_MEMORY_BASIC_INFORMATION) == 4, alignment(_MEMORY_BASIC_INFORMATION)
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1539
class _FLOATING_SAVE_AREA(Structure):
    pass
_FLOATING_SAVE_AREA._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1539
    ('ControlWord', DWORD),
    ('StatusWord', DWORD),
    ('TagWord', DWORD),
    ('ErrorOffset', DWORD),
    ('ErrorSelector', DWORD),
    ('DataOffset', DWORD),
    ('DataSelector', DWORD),
    ('RegisterArea', BYTE * 80),
    ('Cr0NpxState', DWORD),
]
#assert sizeof(_FLOATING_SAVE_AREA) == 112, sizeof(_FLOATING_SAVE_AREA)
#assert alignment(_FLOATING_SAVE_AREA) == 4, alignment(_FLOATING_SAVE_AREA)
FLOATING_SAVE_AREA = _FLOATING_SAVE_AREA
_CONTEXT._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 1563
    ('ContextFlags', DWORD),
    ('Dr0', DWORD),
    ('Dr1', DWORD),
    ('Dr2', DWORD),
    ('Dr3', DWORD),
    ('Dr6', DWORD),
    ('Dr7', DWORD),
    ('FloatSave', FLOATING_SAVE_AREA),
    ('SegGs', DWORD),
    ('SegFs', DWORD),
    ('SegEs', DWORD),
    ('SegDs', DWORD),
    ('Edi', DWORD),
    ('Esi', DWORD),
    ('Ebx', DWORD),
    ('Edx', DWORD),
    ('Ecx', DWORD),
    ('Eax', DWORD),
    ('Ebp', DWORD),
    ('Eip', DWORD),
    ('SegCs', DWORD),
    ('EFlags', DWORD),
    ('Esp', DWORD),
    ('SegSs', DWORD),
    ('Rip', DWORD),
    ('Rax', DWORD),
    ('Rbx', DWORD),
    ('Rcx', DWORD),
    ('Rdx', DWORD),
    ('Rdi', DWORD),
    ('Rsi', DWORD),
    ('Rbp', DWORD),
    ('Rsp', DWORD),
    ('RFlags', DWORD),
    ('R8', DWORD),
    ('R9', DWORD),
    ('R10', DWORD),
    ('R11', DWORD),
    ('R12', DWORD),
    ('R13', DWORD),
    ('R14', DWORD),
    ('R15', DWORD),
    ('R0', DWORD),
    ('R1', DWORD),
    ('R2', DWORD),
    ('R3', DWORD),
    ('R4', DWORD),
    ('R5', DWORD),
    ('R6', DWORD),
    ('R7', DWORD),
    ('SP', DWORD),
    ('LR', DWORD),
    ('PC', DWORD),
    ('CPSR', DWORD),
    ('ExtendedRegisters', BYTE * 512),
]
#assert sizeof(_CONTEXT) == 716, sizeof(_CONTEXT)
#assert alignment(_CONTEXT) == 4, alignment(_CONTEXT)
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 498
class N12_SYSTEM_INFO4DOLLAR_37E(Union):
    pass
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 500
class N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E(Structure):
    pass
N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 500
    ('wProcessorArchitecture', WORD),
    ('wReserved', WORD),
]
#assert sizeof(N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E) == 4, sizeof(N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E)
#assert alignment(N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E) == 2, alignment(N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E)
N12_SYSTEM_INFO4DOLLAR_37E._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 498
    ('dwOemId', DWORD),
    # Unnamed field renamed to '_'
    ('_', N12_SYSTEM_INFO4DOLLAR_374DOLLAR_38E),
]
#assert sizeof(N12_SYSTEM_INFO4DOLLAR_37E) == 4, sizeof(N12_SYSTEM_INFO4DOLLAR_37E)
#assert alignment(N12_SYSTEM_INFO4DOLLAR_37E) == 4, alignment(N12_SYSTEM_INFO4DOLLAR_37E)
LPVOID = c_void_p
_SYSTEM_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 497
    # Unnamed field renamed to '_'
    ('_', N12_SYSTEM_INFO4DOLLAR_37E),
    ('dwPageSize', DWORD),
    ('lpMinimumApplicationAddress', LPVOID),
    ('lpMaximumApplicationAddress', LPVOID),
    ('dwActiveProcessorMask', DWORD),
    ('dwNumberOfProcessors', DWORD),
    ('dwProcessorType', DWORD),
    ('dwAllocationGranularity', DWORD),
    ('wProcessorLevel', WORD),
    ('wProcessorRevision', WORD),
]
#assert sizeof(_SYSTEM_INFO) == 36, sizeof(_SYSTEM_INFO)
#assert alignment(_SYSTEM_INFO) == 4, alignment(_SYSTEM_INFO)
CHAR = c_char
LPSTR = POINTER(CHAR)
LPBYTE = POINTER(BYTE)
_STARTUPINFOA._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 3774
    ('cb', DWORD),
    ('lpReserved', LPSTR),
    ('lpDesktop', LPSTR),
    ('lpTitle', LPSTR),
    ('dwX', DWORD),
    ('dwY', DWORD),
    ('dwXSize', DWORD),
    ('dwYSize', DWORD),
    ('dwXCountChars', DWORD),
    ('dwYCountChars', DWORD),
    ('dwFillAttribute', DWORD),
    ('dwFlags', DWORD),
    ('wShowWindow', WORD),
    ('cbReserved2', WORD),
    ('lpReserved2', LPBYTE),
    ('hStdInput', HANDLE),
    ('hStdOutput', HANDLE),
    ('hStdError', HANDLE),
]
#assert sizeof(_STARTUPINFOA) == 68, sizeof(_STARTUPINFOA)
#assert alignment(_STARTUPINFOA) == 4, alignment(_STARTUPINFOA)
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 701
class N12_DEBUG_EVENT4DOLLAR_39E(Union):
    pass
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 640
class _EXCEPTION_DEBUG_INFO(Structure):
    pass
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 3101
class _EXCEPTION_RECORD(Structure):
    pass
_EXCEPTION_RECORD._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 3101
    ('ExceptionCode', DWORD),
    ('ExceptionFlags', DWORD),
    ('ExceptionRecord', POINTER(_EXCEPTION_RECORD)),
    ('ExceptionAddress', PVOID),
    ('NumberParameters', DWORD),
    ('ExceptionInformation', UINT_PTR * 15),
]
#assert sizeof(_EXCEPTION_RECORD) == 80, sizeof(_EXCEPTION_RECORD)
#assert alignment(_EXCEPTION_RECORD) == 4, alignment(_EXCEPTION_RECORD)
EXCEPTION_RECORD = _EXCEPTION_RECORD
_EXCEPTION_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 640
    ('ExceptionRecord', EXCEPTION_RECORD),
    ('dwFirstChance', DWORD),
]
#assert sizeof(_EXCEPTION_DEBUG_INFO) == 84, sizeof(_EXCEPTION_DEBUG_INFO)
#assert alignment(_EXCEPTION_DEBUG_INFO) == 4, alignment(_EXCEPTION_DEBUG_INFO)
EXCEPTION_DEBUG_INFO = _EXCEPTION_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 645
class _CREATE_THREAD_DEBUG_INFO(Structure):
    pass

# macos compatability.
try:
    PTHREAD_START_ROUTINE = WINFUNCTYPE(DWORD, c_void_p)
except:
    PTHREAD_START_ROUTINE = CFUNCTYPE(DWORD, c_void_p)

LPTHREAD_START_ROUTINE = PTHREAD_START_ROUTINE
_CREATE_THREAD_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 645
    ('hThread', HANDLE),
    ('lpThreadLocalBase', LPVOID),
    ('lpStartAddress', LPTHREAD_START_ROUTINE),
]
#assert sizeof(_CREATE_THREAD_DEBUG_INFO) == 12, sizeof(_CREATE_THREAD_DEBUG_INFO)
#assert alignment(_CREATE_THREAD_DEBUG_INFO) == 4, alignment(_CREATE_THREAD_DEBUG_INFO)
CREATE_THREAD_DEBUG_INFO = _CREATE_THREAD_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 651
class _CREATE_PROCESS_DEBUG_INFO(Structure):
    pass
_CREATE_PROCESS_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 651
    ('hFile', HANDLE),
    ('hProcess', HANDLE),
    ('hThread', HANDLE),
    ('lpBaseOfImage', LPVOID),
    ('dwDebugInfoFileOffset', DWORD),
    ('nDebugInfoSize', DWORD),
    ('lpThreadLocalBase', LPVOID),
    ('lpStartAddress', LPTHREAD_START_ROUTINE),
    ('lpImageName', LPVOID),
    ('fUnicode', WORD),
]
#assert sizeof(_CREATE_PROCESS_DEBUG_INFO) == 40, sizeof(_CREATE_PROCESS_DEBUG_INFO)
#assert alignment(_CREATE_PROCESS_DEBUG_INFO) == 4, alignment(_CREATE_PROCESS_DEBUG_INFO)
CREATE_PROCESS_DEBUG_INFO = _CREATE_PROCESS_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 664
class _EXIT_THREAD_DEBUG_INFO(Structure):
    pass
_EXIT_THREAD_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 664
    ('dwExitCode', DWORD),
]
#assert sizeof(_EXIT_THREAD_DEBUG_INFO) == 4, sizeof(_EXIT_THREAD_DEBUG_INFO)
#assert alignment(_EXIT_THREAD_DEBUG_INFO) == 4, alignment(_EXIT_THREAD_DEBUG_INFO)
EXIT_THREAD_DEBUG_INFO = _EXIT_THREAD_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 668
class _EXIT_PROCESS_DEBUG_INFO(Structure):
    pass
_EXIT_PROCESS_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 668
    ('dwExitCode', DWORD),
]
#assert sizeof(_EXIT_PROCESS_DEBUG_INFO) == 4, sizeof(_EXIT_PROCESS_DEBUG_INFO)
#assert alignment(_EXIT_PROCESS_DEBUG_INFO) == 4, alignment(_EXIT_PROCESS_DEBUG_INFO)
EXIT_PROCESS_DEBUG_INFO = _EXIT_PROCESS_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 672
class _LOAD_DLL_DEBUG_INFO(Structure):
    pass
_LOAD_DLL_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 672
    ('hFile', HANDLE),
    ('lpBaseOfDll', LPVOID),
    ('dwDebugInfoFileOffset', DWORD),
    ('nDebugInfoSize', DWORD),
    ('lpImageName', LPVOID),
    ('fUnicode', WORD),
]
#assert sizeof(_LOAD_DLL_DEBUG_INFO) == 24, sizeof(_LOAD_DLL_DEBUG_INFO)
#assert alignment(_LOAD_DLL_DEBUG_INFO) == 4, alignment(_LOAD_DLL_DEBUG_INFO)
LOAD_DLL_DEBUG_INFO = _LOAD_DLL_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 681
class _UNLOAD_DLL_DEBUG_INFO(Structure):
    pass
_UNLOAD_DLL_DEBUG_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 681
    ('lpBaseOfDll', LPVOID),
]
#assert sizeof(_UNLOAD_DLL_DEBUG_INFO) == 4, sizeof(_UNLOAD_DLL_DEBUG_INFO)
#assert alignment(_UNLOAD_DLL_DEBUG_INFO) == 4, alignment(_UNLOAD_DLL_DEBUG_INFO)
UNLOAD_DLL_DEBUG_INFO = _UNLOAD_DLL_DEBUG_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 685
class _OUTPUT_DEBUG_STRING_INFO(Structure):
    pass
_OUTPUT_DEBUG_STRING_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 685
    ('lpDebugStringData', LPSTR),
    ('fUnicode', WORD),
    ('nDebugStringLength', WORD),
]
#assert sizeof(_OUTPUT_DEBUG_STRING_INFO) == 8, sizeof(_OUTPUT_DEBUG_STRING_INFO)
#assert alignment(_OUTPUT_DEBUG_STRING_INFO) == 4, alignment(_OUTPUT_DEBUG_STRING_INFO)
OUTPUT_DEBUG_STRING_INFO = _OUTPUT_DEBUG_STRING_INFO
# C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 691
class _RIP_INFO(Structure):
    pass
_RIP_INFO._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 691
    ('dwError', DWORD),
    ('dwType', DWORD),
]
#assert sizeof(_RIP_INFO) == 8, sizeof(_RIP_INFO)
#assert alignment(_RIP_INFO) == 4, alignment(_RIP_INFO)
RIP_INFO = _RIP_INFO
N12_DEBUG_EVENT4DOLLAR_39E._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 701
    ('Exception', EXCEPTION_DEBUG_INFO),
    ('CreateThread', CREATE_THREAD_DEBUG_INFO),
    ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
    ('ExitThread', EXIT_THREAD_DEBUG_INFO),
    ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
    ('LoadDll', LOAD_DLL_DEBUG_INFO),
    ('UnloadDll', UNLOAD_DLL_DEBUG_INFO),
    ('DebugString', OUTPUT_DEBUG_STRING_INFO),
    ('RipInfo', RIP_INFO),
]
#assert sizeof(N12_DEBUG_EVENT4DOLLAR_39E) == 84, sizeof(N12_DEBUG_EVENT4DOLLAR_39E)
#assert alignment(N12_DEBUG_EVENT4DOLLAR_39E) == 4, alignment(N12_DEBUG_EVENT4DOLLAR_39E)
_DEBUG_EVENT._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 697
    ('dwDebugEventCode', DWORD),
    ('dwProcessId', DWORD),
    ('dwThreadId', DWORD),
    ('u', N12_DEBUG_EVENT4DOLLAR_39E),
]
#assert sizeof(_DEBUG_EVENT) == 96, sizeof(_DEBUG_EVENT)
#assert alignment(_DEBUG_EVENT) == 4, alignment(_DEBUG_EVENT)
LONG = c_long
_LUID._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 394
    ('LowPart', DWORD),
    ('HighPart', LONG),
]
#assert sizeof(_LUID) == 8, sizeof(_LUID)
#assert alignment(_LUID) == 4, alignment(_LUID)
# C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 3241
class _LUID_AND_ATTRIBUTES(Structure):
    pass
_LUID_AND_ATTRIBUTES._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 3241
    ('Luid', LUID),
    ('Attributes', DWORD),
]
#assert sizeof(_LUID_AND_ATTRIBUTES) == 12, sizeof(_LUID_AND_ATTRIBUTES)
#assert alignment(_LUID_AND_ATTRIBUTES) == 4, alignment(_LUID_AND_ATTRIBUTES)
LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES
_TOKEN_PRIVILEGES._fields_ = [
    # C:/PROGRA~1/gccxml/bin/Vc6/Include/winnt.h 4188
    ('PrivilegeCount', DWORD),
    ('Privileges', LUID_AND_ATTRIBUTES * 1),
]
#assert sizeof(_TOKEN_PRIVILEGES) == 16, sizeof(_TOKEN_PRIVILEGES)
#assert alignment(_TOKEN_PRIVILEGES) == 4, alignment(_TOKEN_PRIVILEGES)
# FIXME - original is HANDLE instead of c_int
# but in the DLL HANDLE is INT while here it's c_void_p (void *)
# so it generates problems in 64bits mode
_PROCESS_INFORMATION._fields_ = [
    # C:/PROGRA~1/MICROS~2/VC98/Include/winbase.h 229
    ('hProcess', c_int),
    ('hThread', c_int),
    ('dwProcessId', DWORD),
    ('dwThreadId', DWORD),
]
#assert sizeof(_PROCESS_INFORMATION) == 16, sizeof(_PROCESS_INFORMATION)
#assert alignment(_PROCESS_INFORMATION) == 4, alignment(_PROCESS_INFORMATION)
