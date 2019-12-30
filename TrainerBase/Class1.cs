using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CheatEngine
{

    enum TScanOption { soUnknownValue = 0, soExactValue = 1, soValueBetween = 2, soBiggerThan = 3, soSmallerThan = 4, soIncreasedValue = 5, soIncreasedValueBy = 6, soDecreasedValue = 7, soDecreasedValueBy = 8, soChanged = 9, soUnchanged = 10, soCustom };
    enum TScanType { stNewScan, stFirstScan, stNextScan };
    enum TRoundingType { rtRounded = 0, rtExtremerounded = 1, rtTruncated = 2 };
    enum TVariableType { vtByte = 0, vtWord = 1, vtDword = 2, vtQword = 3, vtSingle = 4, vtDouble = 5, vtString = 6, vtUnicodeString = 7, vtByteArray = 8, vtBinary = 9, vtAll = 10, vtAutoAssembler = 11, vtPointer = 12, vtCustom = 13, vtGrouped = 14, vtByteArrays = 15 }; //all ,grouped and MultiByteArray are special types
    enum TCustomScanType { cstNone, cstAutoAssembler, cstCPP, cstDLLFunction };
    enum TFastScanMethod { fsmNotAligned = 0, fsmAligned = 1, fsmLastDigits = 2 };
    enum Tscanregionpreference { scanDontCare, scanExclude, scanInclude };

    class CheatEngineLibrary
    {

        // Static invocations.
        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        extern static IntPtr LoadLibraryW(String strLib);

        [DllImport("kernel32.dll")]
        extern static IntPtr LoadLibrary(String strLib);

        [DllImport("kernel32.dll")]
        extern static int FreeLibrary(IntPtr iModule);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Winapi)]
        extern static IntPtr GetProcAddress(IntPtr iModule, String strProcName);

        public delegate void IGetProcessList([MarshalAs(UnmanagedType.BStr)] out string processes);
        public delegate void IOpenProcess([MarshalAs(UnmanagedType.BStr)] string pid);

        public delegate void IResetTable();
        public delegate void IAddScript([MarshalAs(UnmanagedType.BStr)] string name, [MarshalAs(UnmanagedType.BStr)] string script);
        public delegate void IActivateRecord(int id, bool activate);
        public delegate void IRemoveRecord(int id);
        public delegate void IApplyFreeze();

        public delegate void IAddAddressManually([MarshalAs(UnmanagedType.BStr)] string initialaddress,
        TVariableType vartype);
        public delegate void IGetValue(int id, [MarshalAs(UnmanagedType.BStr)] out string value);
        public delegate void ISetValue(int id, [MarshalAs(UnmanagedType.BStr)] string value, bool freezer);
        public delegate void IProcessAddress([MarshalAs(UnmanagedType.BStr)] string address, TVariableType vartype,
         bool showashexadecimal, bool showAsSigned, int bytesize, [MarshalAs(UnmanagedType.BStr)] out string value);

        public delegate void IInitMemoryScanner(int handle);
        public delegate void INewScan();
        public delegate void IConfigScanner(Tscanregionpreference scanWritable, Tscanregionpreference scanExecutable, Tscanregionpreference scanCopyOnWrite);

        public delegate void IFirstScan(TScanOption scanOption, TVariableType variableType,
  TRoundingType roundingtype, [MarshalAs(UnmanagedType.BStr)] string scanvalue1,
   [MarshalAs(UnmanagedType.BStr)] string scanvalue2, [MarshalAs(UnmanagedType.BStr)] string startaddress,
   [MarshalAs(UnmanagedType.BStr)] string stopaddress, bool hexadecimal, bool binaryStringAsDecimal,
   bool unicode, bool casesensitive, TFastScanMethod fastscanmethod,
   [MarshalAs(UnmanagedType.BStr)] string fastscanparameter);

        public delegate void INextScan(TScanOption scanOption, TRoundingType roundingtype, [MarshalAs(UnmanagedType.BStr)] string scanvalue1,
 [MarshalAs(UnmanagedType.BStr)] string scanvalue2, bool hexadecimal, bool binaryStringAsDecimal,
 bool unicode, bool casesensitive, bool percentage, bool compareToSavedScan, [MarshalAs(UnmanagedType.BStr)] string savedscanname);

        public delegate Int64 ICountAddressesFound();
        public delegate void IGetAddress(Int64 index, [MarshalAs(UnmanagedType.BStr)] out string address, [MarshalAs(UnmanagedType.BStr)] out string value);
        public delegate void IInitFoundList(TVariableType vartype, int varlength, bool hexadecimal, bool signed, bool binaryasdecimal, bool unicode);
        public delegate void IResetValues();
        public delegate int IGetBinarySize();

        private IntPtr libInst;

        public IGetProcessList iGetProcessList;
        public IOpenProcess iOpenProcess;

        public IResetTable iResetTable;
        public IAddScript iAddScript;
        public IRemoveRecord iRemoveRecord;
        public IActivateRecord iActivateRecord;
        public IApplyFreeze iApplyFreeze;

        public IAddAddressManually iAddAddressManually;
        public IGetValue iGetValue;
        public ISetValue iSetValue;
        public IProcessAddress iProcessAddress;


        public IInitMemoryScanner iInitMemoryScanner;
        public INewScan iNewScan;
        public IConfigScanner iConfigScanner;
        public IFirstScan iFirstScan;
        public INextScan iNextScan;
        public ICountAddressesFound iCountAddressesFound;
        public IGetAddress iGetAddress;
        public IInitFoundList iInitFoundList;
        public IResetValues iResetValues;
        public IGetBinarySize iGetBinarySize;
        private void loadFunctions()
        {
            IntPtr pGetProcessList = GetProcAddress(libInst, "IGetProcessList");
            IntPtr pOpenProcess = GetProcAddress(libInst, "IOpenProcess");

            IntPtr pResetTable = GetProcAddress(libInst, "IResetTable");
            IntPtr pAddScript = GetProcAddress(libInst, "IAddScript");
            IntPtr pRemoveRecord = GetProcAddress(libInst, "IRemoveRecord");
            IntPtr pActivateRecord = GetProcAddress(libInst, "IActivateRecord");
            IntPtr pApplyFreeze = GetProcAddress(libInst, "IApplyFreeze");

            IntPtr pAddAddressManually = GetProcAddress(libInst, "IAddAddressManually");
            IntPtr pGetValue = GetProcAddress(libInst, "IGetValue");
            IntPtr pSetValue = GetProcAddress(libInst, "ISetValue");
            IntPtr pProcessAddress = GetProcAddress(libInst, "IProcessAddress");

            IntPtr pInitMemoryScanner = GetProcAddress(libInst, "IInitMemoryScanner");
            IntPtr pNewScan = GetProcAddress(libInst, "INewScan");
            IntPtr pConfigScanner = GetProcAddress(libInst, "IConfigScanner");
            IntPtr pFirstScan = GetProcAddress(libInst, "IFirstScan");
            IntPtr pNextScan = GetProcAddress(libInst, "INextScan");
            IntPtr pCountAddressesFound = GetProcAddress(libInst, "ICountAddressesFound");
            IntPtr pGetAddress = GetProcAddress(libInst, "IGetAddress");
            IntPtr pInitFoundList = GetProcAddress(libInst, "IInitFoundList");
            IntPtr pResetValues = GetProcAddress(libInst, "IResetValues");
            IntPtr pGetBinarySize = GetProcAddress(libInst, "IGetBinarySize");

            iGetProcessList = (IGetProcessList)Marshal.GetDelegateForFunctionPointer(pGetProcessList, typeof(IGetProcessList));
            iOpenProcess = (IOpenProcess)Marshal.GetDelegateForFunctionPointer(pOpenProcess, typeof(IOpenProcess));

            iResetTable = (IResetTable)Marshal.GetDelegateForFunctionPointer(pResetTable, typeof(IResetTable));
            iAddScript = (IAddScript)Marshal.GetDelegateForFunctionPointer(pAddScript, typeof(IAddScript));
            iRemoveRecord = (IRemoveRecord)Marshal.GetDelegateForFunctionPointer(pRemoveRecord, typeof(IRemoveRecord));
            iActivateRecord = (IActivateRecord)Marshal.GetDelegateForFunctionPointer(pActivateRecord, typeof(IActivateRecord));
            iApplyFreeze = (IApplyFreeze)Marshal.GetDelegateForFunctionPointer(pApplyFreeze, typeof(IApplyFreeze));

            iAddAddressManually = (IAddAddressManually)Marshal.GetDelegateForFunctionPointer(pAddAddressManually, typeof(IAddAddressManually));
            iGetValue = (IGetValue)Marshal.GetDelegateForFunctionPointer(pGetValue, typeof(IGetValue));
            iSetValue = (ISetValue)Marshal.GetDelegateForFunctionPointer(pSetValue, typeof(ISetValue));
            iProcessAddress = (IProcessAddress)Marshal.GetDelegateForFunctionPointer(pProcessAddress, typeof(IProcessAddress));

            iInitMemoryScanner = (IInitMemoryScanner)Marshal.GetDelegateForFunctionPointer(pInitMemoryScanner, typeof(IInitMemoryScanner));
            iNewScan = (INewScan)Marshal.GetDelegateForFunctionPointer(pNewScan, typeof(INewScan));
            iConfigScanner = (IConfigScanner)Marshal.GetDelegateForFunctionPointer(pConfigScanner, typeof(IConfigScanner));
            iFirstScan = (IFirstScan)Marshal.GetDelegateForFunctionPointer(pFirstScan, typeof(IFirstScan));
            iNextScan = (INextScan)Marshal.GetDelegateForFunctionPointer(pNextScan, typeof(INextScan));

            iCountAddressesFound = (ICountAddressesFound)Marshal.GetDelegateForFunctionPointer(pCountAddressesFound, typeof(ICountAddressesFound));
            iGetAddress = (IGetAddress)Marshal.GetDelegateForFunctionPointer(pGetAddress, typeof(IGetAddress));
            iInitFoundList = (IInitFoundList)Marshal.GetDelegateForFunctionPointer(pInitFoundList, typeof(IInitFoundList));
            iResetValues = (IResetValues)Marshal.GetDelegateForFunctionPointer(pResetValues, typeof(IResetValues));
            iGetBinarySize = (IGetBinarySize)Marshal.GetDelegateForFunctionPointer(pGetBinarySize, typeof(IGetBinarySize));
        }
        public void loadEngine()
        {

            
            libInst = LoadLibraryW(TrainerBase.kakak.ggg);

            if (libInst != IntPtr.Zero)
            {
               
                loadFunctions();
            }
            else MessageBox.Show("error, can't load the library");

        }

        public void unloadEngine()
        {
            FreeLibrary(libInst);
        }

    }

}
namespace System.Runtime.ExceptionServices
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
    class HandleProcessCorruptedStateExceptionsAttribute : Attribute
    {
    }
}

namespace shitcracker
{
    public class BabelObfuscatorAttribute : Attribute
    {
    }
    public class DotfuscatorAttribute : Attribute
    {
    }
    public class NineRaysObfuscatorEvaluation : Attribute
    {
    }
    public class EMyPID_8234_ : Attribute
    {
    }
    public class CryptoObfuscator : Attribute
    {
    }
    public class ProtectedWithCryptoObfuscatorAttribute : Attribute
    {
    }
    public class YanoAttribute : Attribute
    {
    }
    public class ZYXDNGuarder : Attribute
    {
    }
    public class ObfuscatedByGoliath : Attribute
    {
    }
    public class ObfuscatedByAgileDotNetAttribute : Attribute
    {
    }
    public class SecureTeam : Attribute
    {
    }
    public class SmartAssembly : Attribute
    {
    }
    public class PoweredByAttribute : Attribute
    {
    }
    public class Xenocode : Attribute
    {
    }
    public class ProcessedByXenocode : Attribute
    {
    }
    public class NETGuard : Attribute
    {
    }
    public class ConfusedByAttribute : Attribute
    {
    }
    public class Protected_By_Attribute : Attribute
    {
    }
    public class NETSpider : Attribute
    {
    }
    public class NetzStarter : Attribute
    {
    }
    public class ArcUpdateABBYY : Attribute
    {
    }
    public class Macrobject
    {
        string fkfk = "Macrobject.Obfuscator";
        string kgkg = "Obfuscated by Macrobject Obfuscator.NET UNREGISTRED";
        string kg = "NineRays.Obfuscator";
        string kgXkg = "Protected/Packed with ReNET-Pack by stx";
    }
}
namespace TrainerBase
{
    public class kakak
    {
        public static string ggg = "";
    }
    public class Win32API
    {
        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(IntPtr ObjectHandle, int
            ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength,
            ref int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(int
            SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength,
            ref int returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr OpenMutex(UInt32 desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           ushort hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        public enum ObjectInformationClass : int
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_BASIC_INFORMATION
        { // Information Class 0
            public int Attributes;
            public int GrantedAccess;
            public int HandleCount;
            public int PointerCount;
            public int PagedPoolUsage;
            public int NonPagedPoolUsage;
            public int Reserved1;
            public int Reserved2;
            public int Reserved3;
            public int NameInformationLength;
            public int TypeInformationLength;
            public int SecurityDescriptorLength;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_TYPE_INFORMATION
        { // Information Class 2
            public UNICODE_STRING Name;
            public int ObjectCount;
            public int HandleCount;
            public int Reserved1;
            public int Reserved2;
            public int Reserved3;
            public int Reserved4;
            public int PeakObjectCount;
            public int PeakHandleCount;
            public int Reserved5;
            public int Reserved6;
            public int Reserved7;
            public int Reserved8;
            public int InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public int ValidAccess;
            public byte Unknown;
            public byte MaintainHandleDatabase;
            public int PoolType;
            public int PagedPoolUsage;
            public int NonPagedPoolUsage;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_NAME_INFORMATION
        { // Information Class 1
            public UNICODE_STRING Name;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_MAPPING
        {
            public int GenericRead;
            public int GenericWrite;
            public int GenericExecute;
            public int GenericAll;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE_INFORMATION
        { // Information Class 16
            public int ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public UInt32 GrantedAccess;
        }

        public const int MAX_PATH = 260;
        public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        public const int DUPLICATE_SAME_ACCESS = 0x2;
        public const int DUPLICATE_CLOSE_SOURCE = 0x1;
    }
    public static class AntiManagedProfiler
    {
        static IProfilerDetector profilerDetector;

        interface IProfilerDetector
        {
            bool IsProfilerAttached { get; }
            bool WasProfilerAttached { get; }
            bool Initialize();
            void PreventActiveProfilerFromReceivingProfilingMessages();
        }

        class ProfilerDetectorCLR20 : IProfilerDetector
        {
            /// <summary>
            /// Address of CLR 2.0's profiler status flag. If one or both of bits 1 or 2 is set,
            /// a profiler is attached.
            /// </summary>
            IntPtr profilerStatusFlag;

            bool wasAttached;

            public bool IsProfilerAttached
            {
                get
                {
                    unsafe
                    {
                        if (profilerStatusFlag == IntPtr.Zero)
                            return false;
                        return (*(uint*)profilerStatusFlag & 6) != 0;
                    }
                }
            }

            public bool WasProfilerAttached
            {
                get { return wasAttached; }
            }

            public bool Initialize()
            {
                bool result = FindProfilerStatus();
                wasAttached = IsProfilerAttached;
                return result;
            }

            /// <summary>
            /// This code tries to find the CLR 2.0 profiler status flag. It searches the whole
            /// .text section for a certain instruction.
            /// </summary>
            /// <returns><c>true</c> if it was found, <c>false</c> otherwise</returns>
            unsafe bool FindProfilerStatus()
            {
                // Record each hit here and pick the one with the most hits
                var addrCounts = new Dictionary<IntPtr, int>();
                try
                {
                    var peInfo = PEInfo.GetCLR();
                    if (peInfo == null)
                        return false;

                    IntPtr sectionAddr;
                    uint sectionSize;
                    if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
                        return false;

                    const int MAX_COUNTS = 50;
                    byte* p = (byte*)sectionAddr;
                    byte* end = (byte*)sectionAddr + sectionSize;
                    for (; p < end; p++)
                    {
                        IntPtr addr;

                        // F6 05 XX XX XX XX 06	test byte ptr [mem],6
                        if (*p == 0xF6 && p[1] == 0x05 && p[6] == 0x06)
                        {
                            if (IntPtr.Size == 4)
                                addr = new IntPtr((void*)*(uint*)(p + 2));
                            else
                                addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
                        }
                        else
                            continue;

                        if (!PEInfo.IsAligned(addr, 4))
                            continue;
                        if (!peInfo.IsValidImageAddress(addr, 4))
                            continue;

                        try
                        {
                            *(uint*)addr = *(uint*)addr;
                        }
                        catch
                        {
                            continue;
                        }

                        int count = 0;
                        addrCounts.TryGetValue(addr, out count);
                        count++;
                        addrCounts[addr] = count;
                        if (count >= MAX_COUNTS)
                            break;
                    }
                }
                catch
                {
                }
                var foundAddr = GetMax(addrCounts, 5);
                if (foundAddr == IntPtr.Zero)
                    return false;

                profilerStatusFlag = foundAddr;
                return true;
            }

            public unsafe void PreventActiveProfilerFromReceivingProfilingMessages()
            {
                if (profilerStatusFlag == IntPtr.Zero)
                    return;
                *(uint*)profilerStatusFlag &= ~6U;
            }
        }

        class ProfilerDetectorCLR40 : IProfilerDetector
        {
            const uint PIPE_ACCESS_DUPLEX = 3;
            const uint PIPE_TYPE_MESSAGE = 4;
            const uint PIPE_READMODE_MESSAGE = 2;
            const uint FILE_FLAG_OVERLAPPED = 0x40000000;
            const uint GENERIC_READ = 0x80000000;
            const uint GENERIC_WRITE = 0x40000000;
            const uint OPEN_EXISTING = 3;
            const uint PAGE_EXECUTE_READWRITE = 0x40;

            [DllImport("kernel32", CharSet = CharSet.Auto)]
            static extern uint GetCurrentProcessId();

            [DllImport("kernel32", CharSet = CharSet.Auto)]
            static extern void Sleep(uint dwMilliseconds);

            [DllImport("kernel32", SetLastError = true)]
            static extern SafeFileHandle CreateNamedPipe(string lpName, uint dwOpenMode,
               uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
               uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

            [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
            static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
               uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
               uint dwFlagsAndAttributes, IntPtr hTemplateFile);

            [DllImport("kernel32")]
            static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

            const uint ConfigDWORDInfo_name = 0;
            static readonly uint ConfigDWORDInfo_defValue = (uint)IntPtr.Size;
            const string ProfAPIMaxWaitForTriggerMs_name = "ProfAPIMaxWaitForTriggerMs";

            /// <summary>
            /// Address of the profiler control block. Only some fields are interesting and
            /// here they are in order:
            /// 
            /// <code>
            /// EEToProfInterfaceImpl*
            /// uint profilerEventMask
            /// uint profilerStatus
            /// </code>
            /// 
            /// <c>profilerStatus</c> is <c>0</c> when no profiler is attached. Any other value
            /// indicates that a profiler is attached, attaching, or detaching. It's <c>4</c>
            /// when a profiler is attached. When it's attached, it will receive messages from
            /// the CLR.
            /// </summary>
            IntPtr profilerControlBlock;

            SafeFileHandle profilerPipe;

            bool wasAttached;

            public bool IsProfilerAttached
            {
                get
                {
                    unsafe
                    {
                        if (profilerControlBlock == IntPtr.Zero)
                            return false;
                        return *(uint*)((byte*)profilerControlBlock + IntPtr.Size + 4) != 0;
                    }
                }
            }

            public bool WasProfilerAttached
            {
                get { return wasAttached; }
            }

            public bool Initialize()
            {
                bool result = FindProfilerControlBlock();
                result &= TakeOwnershipOfNamedPipe() || CreateNamedPipe();
                result &= PatchAttacherThreadProc();
                wasAttached = IsProfilerAttached;
                return result;
            }

            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe bool TakeOwnershipOfNamedPipe()
            {
                try
                {
                    if (CreateNamedPipe())
                        return true;

                    // The CLR has already created the named pipe. Either the AttachThreadAlwaysOn
                    // CLR option is enabled or some profiler has just attached or is attaching.
                    // We must force it to exit its loop. There are two options that can prevent
                    // it from exiting the thread, AttachThreadAlwaysOn and
                    // ProfAPIMaxWaitForTriggerMs. If AttachThreadAlwaysOn is enabled, the thread
                    // is started immediately when the CLR is loaded and it never exits.
                    // ProfAPIMaxWaitForTriggerMs is the timeout in ms to use when waiting on
                    // client attach messages. A user could set this to FFFFFFFF which is equal
                    // to the INFINITE constant.
                    //
                    // To force it to exit, we must do this:
                    //	- Find clr!ProfilingAPIAttachDetach::s_attachThreadingMode and make sure
                    //	  it's not 2 (AttachThreadAlwaysOn is enabled).
                    //	- Find clr!EXTERNAL_ProfAPIMaxWaitForTriggerMs and:
                    //		- Set its default value to 0
                    //		- Rename the option so the user can't override it
                    //	- Open the named pipe to wake it up and then close the file to force a
                    //	  timeout error.
                    //	- Wait a little while until the thread has exited

                    IntPtr threadingModeAddr = FindThreadingModeAddress();
                    IntPtr timeOutOptionAddr = FindTimeOutOptionAddress();

                    if (timeOutOptionAddr == IntPtr.Zero)
                        return false;

                    // Make sure the thread can exit. If this value is 2, it will never exit.
                    if (threadingModeAddr != IntPtr.Zero && *(uint*)threadingModeAddr == 2)
                        *(uint*)threadingModeAddr = 1;

                    // Set default timeout to 0 and rename timeout option
                    FixTimeOutOption(timeOutOptionAddr);

                    // Wake up clr!ProfilingAPIAttachServer::ConnectToClient(). We immediately
                    // close the pipe so it will fail to read any data. It will then start over
                    // again but this time, its timeout value will be 0, and it will fail. Since
                    // the thread can now exit, it will exit and close its named pipe.
                    using (var hPipe = CreatePipeFileHandleWait())
                    {
                        if (hPipe == null)
                            return false;
                        if (hPipe.IsInvalid)
                            return false;
                    }

                    return CreateNamedPipeWait();
                }
                catch
                {
                }
                return false;
            }

            bool CreateNamedPipeWait()
            {
                int timeLeft = 100;
                const int waitTime = 5;
                while (timeLeft > 0)
                {
                    if (CreateNamedPipe())
                        return true;
                    Sleep(waitTime);
                    timeLeft -= waitTime;
                }
                return CreateNamedPipe();
            }

            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe static void FixTimeOutOption(IntPtr timeOutOptionAddr)
            {
                if (timeOutOptionAddr == IntPtr.Zero)
                    return;

                uint oldProtect;
                VirtualProtect(timeOutOptionAddr, (int)ConfigDWORDInfo_defValue + 4, PAGE_EXECUTE_READWRITE, out oldProtect);
                try
                {
                    // Set default timeout to 0 to make sure it fails immediately
                    *(uint*)((byte*)timeOutOptionAddr + ConfigDWORDInfo_defValue) = 0;

                }
                finally
                {
                    VirtualProtect(timeOutOptionAddr, (int)ConfigDWORDInfo_defValue + 4, oldProtect, out oldProtect);
                }

                // Rename the option to make sure the user can't override the value
                char* name = *(char**)((byte*)timeOutOptionAddr + ConfigDWORDInfo_name);
                IntPtr nameAddr = new IntPtr(name);
                VirtualProtect(nameAddr, ProfAPIMaxWaitForTriggerMs_name.Length * 2, PAGE_EXECUTE_READWRITE, out oldProtect);
                try
                {
                    var rand = new Random();
                    for (int i = 0; i < ProfAPIMaxWaitForTriggerMs_name.Length; i++)
                        name[i] = (char)rand.Next(1, ushort.MaxValue);
                }
                finally
                {
                    VirtualProtect(nameAddr, IntPtr.Size, oldProtect, out oldProtect);
                }
            }

            SafeFileHandle CreatePipeFileHandleWait()
            {
                int timeLeft = 100;
                const int waitTime = 5;
                while (timeLeft > 0)
                {
                    if (CreateNamedPipe())
                        return null;
                    var hFile = CreatePipeFileHandle();
                    if (!hFile.IsInvalid)
                        return hFile;
                    Sleep(waitTime);
                    timeLeft -= waitTime;
                }
                return CreatePipeFileHandle();
            }

            static SafeFileHandle CreatePipeFileHandle()
            {
                return CreateFile(GetPipeName(), GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
            }

            static string GetPipeName()
            {
                return string.Format(@"\\.\pipe\CPFATP_{0}_v{1}.{2}.{3}",
                            GetCurrentProcessId(), Environment.Version.Major,
                            Environment.Version.Minor, Environment.Version.Build);
            }

            bool CreateNamedPipe()
            {
                if (profilerPipe != null && !profilerPipe.IsInvalid)
                    return true;

                profilerPipe = CreateNamedPipe(GetPipeName(),
                                            FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX,
                                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                                            1,          // nMaxInstances
                                            0x24,       // nOutBufferSize
                                            0x338,      // nInBufferSize
                                            1000,       // nDefaultTimeOut
                                            IntPtr.Zero);   // lpSecurityAttributes

                return !profilerPipe.IsInvalid;
            }

            /// <summary>
            /// Finds the address of clr!ProfilingAPIAttachDetach::s_attachThreadingMode
            /// </summary>
            /// <returns>The address or <c>null</c> if none was found</returns>
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            static unsafe IntPtr FindThreadingModeAddress()
            {
                try
                {
                    // Find this code in clr!ProfilingAPIAttachServer::ExecutePipeRequests()
                    //	83 3D XX XX XX XX 02	cmp dword ptr [mem],2
                    //	74 / 0F 84 XX			je there
                    //	83 E8+r 00 / 85 C0+rr	sub reg,0 / test reg,reg
                    //	74 / 0F 84 XX			je there
                    //	48+r / FF C8+r			dec reg
                    //	74 / 0F 84 XX			je there
                    //	48+r / FF C8+r			dec reg

                    var peInfo = PEInfo.GetCLR();
                    if (peInfo == null)
                        return IntPtr.Zero;

                    IntPtr sectionAddr;
                    uint sectionSize;
                    if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
                        return IntPtr.Zero;

                    byte* ptr = (byte*)sectionAddr;
                    byte* end = (byte*)sectionAddr + sectionSize;
                    for (; ptr < end; ptr++)
                    {
                        IntPtr addr;

                        try
                        {
                            //	83 3D XX XX XX XX 02	cmp dword ptr [mem],2
                            byte* p = ptr;
                            if (*p != 0x83 || p[1] != 0x3D || p[6] != 2)
                                continue;
                            if (IntPtr.Size == 4)
                                addr = new IntPtr((void*)*(uint*)(p + 2));
                            else
                                addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
                            if (!PEInfo.IsAligned(addr, 4))
                                continue;
                            if (!peInfo.IsValidImageAddress(addr))
                                continue;
                            p += 7;

                            // 1 = normal lazy thread creation. 2 = thread is always present
                            if (*(uint*)addr < 1 || *(uint*)addr > 2)
                                continue;
                            *(uint*)addr = *(uint*)addr;

                            //	74 / 0F 84 XX			je there
                            if (!NextJz(ref p))
                                continue;

                            //	83 E8+r 00 / 85 C0+rr	sub reg,0 / test reg,reg
                            SkipRex(ref p);
                            if (*p == 0x83 && p[2] == 0)
                            {
                                if ((uint)(p[1] - 0xE8) > 7)
                                    continue;
                                p += 3;
                            }
                            else if (*p == 0x85)
                            {
                                int reg = (p[1] >> 3) & 7;
                                int rm = p[1] & 7;
                                if (reg != rm)
                                    continue;
                                p += 2;
                            }
                            else
                                continue;

                            //	74 / 0F 84 XX			je there
                            if (!NextJz(ref p))
                                continue;

                            //	48+r / FF C8+r			dec reg
                            if (!SkipDecReg(ref p))
                                continue;

                            //	74 / 0F 84 XX			je there
                            if (!NextJz(ref p))
                                continue;

                            //	48+r / FF C8+r			dec reg
                            if (!SkipDecReg(ref p))
                                continue;

                            return addr;
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
                return IntPtr.Zero;
            }

            /// <summary>
            /// Finds the address of clr!EXTERNAL_ProfAPIMaxWaitForTriggerMs
            /// </summary>
            /// <returns>The address or <c>null</c> if none was found</returns>
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            static unsafe IntPtr FindTimeOutOptionAddress()
            {
                try
                {
                    var peInfo = PEInfo.GetCLR();
                    if (peInfo == null)
                        return IntPtr.Zero;

                    IntPtr sectionAddr;
                    uint sectionSize;
                    if (!peInfo.FindSection(".rdata", out sectionAddr, out sectionSize) &&
                        !peInfo.FindSection(".text", out sectionAddr, out sectionSize))
                        return IntPtr.Zero;

                    byte* p = (byte*)sectionAddr;
                    byte* end = (byte*)sectionAddr + sectionSize;
                    for (; p < end; p++)
                    {
                        try
                        {
                            char* name = *(char**)(p + ConfigDWORDInfo_name);
                            if (!PEInfo.IsAligned(new IntPtr(name), 2))
                                continue;
                            if (!peInfo.IsValidImageAddress(name))
                                continue;

                            if (!Equals(name, ProfAPIMaxWaitForTriggerMs_name))
                                continue;

                            return new IntPtr(p);
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
                return IntPtr.Zero;
            }

            unsafe static bool Equals(char* s1, string s2)
            {
                for (int i = 0; i < s2.Length; i++)
                {
                    if (char.ToUpperInvariant(s1[i]) != char.ToUpperInvariant(s2[i]))
                        return false;
                }
                return s1[s2.Length] == 0;
            }

            unsafe static void SkipRex(ref byte* p)
            {
                if (IntPtr.Size != 8)
                    return;
                if (*p >= 0x48 && *p <= 0x4F)
                    p++;
            }

            unsafe static bool SkipDecReg(ref byte* p)
            {
                SkipRex(ref p);
                if (IntPtr.Size == 4 && *p >= 0x48 && *p <= 0x4F)
                    p++;
                else if (*p == 0xFF && p[1] >= 0xC8 && p[1] <= 0xCF)
                    p += 2;
                else
                    return false;
                return true;
            }

            unsafe static bool NextJz(ref byte* p)
            {
                if (*p == 0x74)
                {
                    p += 2;
                    return true;
                }

                if (*p == 0x0F && p[1] == 0x84)
                {
                    p += 6;
                    return true;
                }

                return false;
            }

            /// <summary>
            /// Finds the attacher thread's thread proc and patches it so it returns immediately.
            /// </summary>
            /// <returns><c>true</c> if it was patched, <c>false</c> otherwise</returns>
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe bool PatchAttacherThreadProc()
            {
                IntPtr threadProc = FindAttacherThreadProc();
                if (threadProc == IntPtr.Zero)
                    return false;

                byte* p = (byte*)threadProc;
                uint oldProtect;
                VirtualProtect(new IntPtr(p), 5, PAGE_EXECUTE_READWRITE, out oldProtect);
                try
                {
                    if (IntPtr.Size == 4)
                    {
                        // xor eax,eax
                        p[0] = 0x33; p[1] = 0xC0;
                        // retn 4
                        p[2] = 0xC2; p[3] = 0x04; p[4] = 0x00;
                    }
                    else
                    {
                        // xor eax,eax
                        p[0] = 0x33; p[1] = 0xC0;
                        // retn
                        p[2] = 0xC3;
                    }
                }
                finally
                {
                    VirtualProtect(new IntPtr(p), 5, oldProtect, out oldProtect);
                }
                return true;
            }

            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe IntPtr FindAttacherThreadProc()
            {
                try
                {
                    var peInfo = PEInfo.GetCLR();
                    if (peInfo == null)
                        return IntPtr.Zero;

                    IntPtr sectionAddr;
                    uint sectionSize;
                    if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
                        return IntPtr.Zero;

                    byte* p = (byte*)sectionAddr;
                    byte* start = p;
                    byte* end = (byte*)sectionAddr + sectionSize;

                    if (IntPtr.Size == 4)
                    {
                        for (; p < end; p++)
                        {
                            // Find this code:
                            //	50+r				push reg
                            //	50+r				push reg
                            //	50+r				push reg
                            //	68 XX XX XX XX		push offset ThreadProc
                            //	50+r				push reg
                            //	50+r				push reg
                            //	FF 15 XX XX XX XX	call dword ptr [mem] // CreateThread()

                            byte push = *p;
                            if (push < 0x50 || push > 0x57)
                                continue;
                            if (p[1] != push || p[2] != push || p[8] != push || p[9] != push)
                                continue;
                            if (p[3] != 0x68)
                                continue;
                            if (p[10] != 0xFF || p[11] != 0x15)
                                continue;

                            IntPtr threadProc = new IntPtr((void*)*(uint*)(p + 4));
                            if (!CheckThreadProc(start, end, threadProc))
                                continue;

                            return threadProc;
                        }
                    }
                    else
                    {
                        for (; p < end; p++)
                        {
                            // Find this code:
                            //	45 33 C9				xor r9d,r9d
                            //	4C 8D 05 XX XX XX XX	lea r8,ThreadProc
                            //	33 D2					xor edx,edx
                            //	33 C9					xor ecx,ecx
                            //	FF 15 XX XX XX XX		call dword ptr [mem] // CreateThread()

                            if (*p != 0x45 && p[1] != 0x33 && p[2] != 0xC9)
                                continue;
                            if (p[3] != 0x4C && p[4] != 0x8D && p[5] != 0x05)
                                continue;
                            if (p[10] != 0x33 && p[11] != 0xD2)
                                continue;
                            if (p[12] != 0x33 && p[13] != 0xC9)
                                continue;
                            if (p[14] != 0xFF && p[15] != 0x15)
                                continue;

                            IntPtr threadProc = new IntPtr(p + 10 + *(int*)(p + 6));
                            if (!CheckThreadProc(start, end, threadProc))
                                continue;

                            return threadProc;
                        }
                    }
                }
                catch
                {
                }

                return IntPtr.Zero;
            }

            /// <summary>
            /// Checks whether it appears to be the profiler attacher thread proc
            /// </summary>
            /// <param name="codeStart">Start of code</param>
            /// <param name="codeEnd">End of code</param>
            /// <param name="threadProc">Possible thread proc</param>
            /// <returns><c>true</c> if it's probably the thread proc, <c>false</c> otherwise</returns>
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe static bool CheckThreadProc(byte* codeStart, byte* codeEnd, IntPtr threadProc)
            {
                try
                {
                    byte* p = (byte*)threadProc;

                    // Must be in .text section
                    if (p < codeStart || p >= codeEnd)
                        return false;

                    // It has a constant that is present in the first N bytes
                    for (int i = 0; i < 0x20; i++)
                    {
                        if (*(uint*)(p + i) == 0x4000)
                            return true;
                    }
                }
                catch
                {
                }
                return false;
            }

            /// <summary>
            /// This code tries to find the CLR 4.0 profiler control block address. It does this
            /// by searching for the code that accesses the profiler status field.
            /// </summary>
            /// <returns><c>true</c> if it was found, <c>false</c> otherwise</returns>
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            unsafe bool FindProfilerControlBlock()
            {
                // Record each hit here and pick the one with the most hits
                var addrCounts = new Dictionary<IntPtr, int>();
                try
                {
                    var peInfo = PEInfo.GetCLR();
                    if (peInfo == null)
                        return false;

                    IntPtr sectionAddr;
                    uint sectionSize;
                    if (!peInfo.FindSection(".text", out sectionAddr, out sectionSize))
                        return false;

                    const int MAX_COUNTS = 50;
                    byte* p = (byte*)sectionAddr;
                    byte* end = (byte*)sectionAddr + sectionSize;
                    for (; p < end; p++)
                    {
                        IntPtr addr;

                        // A1 xx xx xx xx		mov eax,[mem]
                        // 83 F8 04				cmp eax,4
                        if (*p == 0xA1 && p[5] == 0x83 && p[6] == 0xF8 && p[7] == 0x04)
                        {
                            if (IntPtr.Size == 4)
                                addr = new IntPtr((void*)*(uint*)(p + 1));
                            else
                                addr = new IntPtr((void*)(p + 5 + *(int*)(p + 1)));
                        }
                        // 8B 05 xx xx xx xx	mov eax,[mem]
                        // 83 F8 04				cmp eax,4
                        else if (*p == 0x8B && p[1] == 0x05 && p[6] == 0x83 && p[7] == 0xF8 && p[8] == 0x04)
                        {
                            if (IntPtr.Size == 4)
                                addr = new IntPtr((void*)*(uint*)(p + 2));
                            else
                                addr = new IntPtr((void*)(p + 6 + *(int*)(p + 2)));
                        }
                        // 83 3D XX XX XX XX 04	cmp dword ptr [mem],4
                        else if (*p == 0x83 && p[1] == 0x3D && p[6] == 0x04)
                        {
                            if (IntPtr.Size == 4)
                                addr = new IntPtr((void*)*(uint*)(p + 2));
                            else
                                addr = new IntPtr((void*)(p + 7 + *(int*)(p + 2)));
                        }
                        else
                            continue;

                        if (!PEInfo.IsAligned(addr, 4))
                            continue;
                        if (!peInfo.IsValidImageAddress(addr, 4))
                            continue;

                        // Valid values are 0-4. 4 being attached.
                        try
                        {
                            if (*(uint*)addr > 4)
                                continue;
                            *(uint*)addr = *(uint*)addr;
                        }
                        catch
                        {
                            continue;
                        }

                        int count = 0;
                        addrCounts.TryGetValue(addr, out count);
                        count++;
                        addrCounts[addr] = count;
                        if (count >= MAX_COUNTS)
                            break;
                    }
                }
                catch
                {
                }
                var foundAddr = GetMax(addrCounts, 5);
                if (foundAddr == IntPtr.Zero)
                    return false;

                profilerControlBlock = new IntPtr((byte*)foundAddr - (IntPtr.Size + 4));
                return true;
            }

            public unsafe void PreventActiveProfilerFromReceivingProfilingMessages()
            {
                if (profilerControlBlock == IntPtr.Zero)
                    return;
                *(uint*)((byte*)profilerControlBlock + IntPtr.Size + 4) = 0;
            }
        }

        /// <summary>
        /// Returns <c>true</c> if a profiler was attached, is attaching or detaching.
        /// </summary>
        public static bool IsProfilerAttached
        {
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            get
            {
                try
                {
                    if (profilerDetector == null)
                        return false;
                    return profilerDetector.IsProfilerAttached;
                }
                catch
                {
                }
                return false;
            }
        }

        /// <summary>
        /// Returns <c>true</c> if a profiler was attached, is attaching or detaching.
        /// </summary>
        public static bool WasProfilerAttached
        {
            [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
            get
            {
                try
                {
                    if (profilerDetector == null)
                        return false;
                    return profilerDetector.WasProfilerAttached;
                }
                catch
                {
                }
                return false;
            }
        }

        /// <summary>
        /// Must be called to initialize anti-managed profiler code. This method should only
        /// be called once per process. I.e., don't call it from every loaded .NET DLL.
        /// </summary>
        /// <returns><c>true</c> if successful, <c>false</c> otherwise</returns>
        public static bool Initialize()
        {
            profilerDetector = CreateProfilerDetector();
            return profilerDetector.Initialize();
        }

        static IProfilerDetector CreateProfilerDetector()
        {
            if (Environment.Version.Major == 2)
                return new ProfilerDetectorCLR20();
            return new ProfilerDetectorCLR40();
        }

        /// <summary>
        /// Prevents any active profiler from receiving any profiling messages. Since the
        /// profiler is still in memory, it can call into the CLR even if it doesn't receive
        /// any messages. It's better to terminate the application than call this method.
        /// </summary>
        public static void PreventActiveProfilerFromReceivingProfilingMessages()
        {
            if (profilerDetector == null)
                return;
            profilerDetector.PreventActiveProfilerFromReceivingProfilingMessages();
        }

        static IntPtr GetMax(Dictionary<IntPtr, int> addresses, int minCount)
        {
            IntPtr foundAddr = IntPtr.Zero;
            int maxCount = 0;

            foreach (var kv in addresses)
            {
                if (foundAddr == IntPtr.Zero || maxCount < kv.Value)
                {
                    foundAddr = kv.Key;
                    maxCount = kv.Value;
                }
            }

            return maxCount >= minCount ? foundAddr : IntPtr.Zero;
        }
    }
    class PEInfo
    {
        IntPtr imageBase;
        IntPtr imageEnd;
        IntPtr sectionsAddr;
        int numSects;

        [DllImport("kernel32", CharSet = CharSet.Auto)]
        static extern IntPtr GetModuleHandle(string name);

        /// <summary>
        /// Creates a <see cref="PEInfo"/> instance loaded from the CLR (clr.dll / mscorwks.dll)
        /// </summary>
        /// <returns>The new instance or <c>null</c> if we failed</returns>
        public static PEInfo GetCLR()
        {
            var clrAddr = GetCLRAddress();
            if (clrAddr == IntPtr.Zero)
                return null;
            return new PEInfo(clrAddr);
        }

        static IntPtr GetCLRAddress()
        {
            if (Environment.Version.Major == 2)
                return GetModuleHandle("mscorwks");
            return GetModuleHandle("clr");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="addr">Address of a PE image</param>
        public PEInfo(IntPtr addr)
        {
            this.imageBase = addr;
            Initialize();
        }

        unsafe void Initialize()
        {
            byte* p = (byte*)imageBase;
            p += *(uint*)(p + 0x3C);    // Get NT headers
            p += 4 + 2; // Skip magic + machine
            numSects = *(ushort*)p;
            p += 2 + 0x10;  // Skip the rest of file header
            bool is32 = *(ushort*)p == 0x010B;
            uint sizeOfImage = *(uint*)(p + 0x38);
            imageEnd = new IntPtr((byte*)imageBase + sizeOfImage);
            p += is32 ? 0x60 : 0x70;    // Skip optional header
            p += 0x10 * 8;      // Skip data dirs
            sectionsAddr = new IntPtr(p);
        }

        /// <summary>
        /// Checks whether the address is within the image
        /// </summary>
        /// <param name="addr">Address</param>
        public unsafe bool IsValidImageAddress(IntPtr addr)
        {
            return IsValidImageAddress((void*)addr, 0);
        }

        /// <summary>
        /// Checks whether the address is within the image
        /// </summary>
        /// <param name="addr">Address</param>
        /// <param name="size">Number of bytes</param>
        public unsafe bool IsValidImageAddress(IntPtr addr, uint size)
        {
            return IsValidImageAddress((void*)addr, size);
        }

        /// <summary>
        /// Checks whether the address is within the image
        /// </summary>
        /// <param name="addr">Address</param>
        public unsafe bool IsValidImageAddress(void* addr)
        {
            return IsValidImageAddress(addr, 0);
        }

        /// <summary>

        public unsafe bool IsValidImageAddress(void* addr, uint size)
        {
            if (addr < (void*)imageBase)
                return false;
            if (addr >= (void*)imageEnd)
                return false;

            if (size != 0)
            {
                if ((byte*)addr + size < (void*)addr)
                    return false;
                if ((byte*)addr + size > (void*)imageEnd)
                    return false;
            }

            return true;
        }

        public unsafe bool FindSection(string name, out IntPtr sectionStart, out uint sectionSize)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name + "\0\0\0\0\0\0\0\0");
            for (int i = 0; i < numSects; i++)
            {
                byte* p = (byte*)sectionsAddr + i * 0x28;
                if (!CompareSectionName(p, nameBytes))
                    continue;

                sectionStart = new IntPtr((byte*)imageBase + *(uint*)(p + 12));
                sectionSize = Math.Max(*(uint*)(p + 8), *(uint*)(p + 16));
                return true;
            }

            sectionStart = IntPtr.Zero;
            sectionSize = 0;
            return false;
        }

        static unsafe bool CompareSectionName(byte* sectionName, byte[] nameBytes)
        {
            for (int i = 0; i < 8; i++)
            {
                if (*sectionName != nameBytes[i])
                    return false;
                sectionName++;
            }
            return true;
        }

     

        public static bool IsAlignedPointer(IntPtr addr)
        {
            return ((int)addr.ToInt64() & (IntPtr.Size - 1)) == 0;
        }

     
        public static bool IsAligned(IntPtr addr, uint alignment)
        {
            return ((uint)addr.ToInt64() & (alignment - 1)) == 0;
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return string.Format("{0:X8} - {1:X8}", (ulong)imageBase.ToInt64(), (ulong)imageEnd.ToInt64());
        }
    }
    public static class AntiManagedDebugger
    {
        [DllImport("kernel32", CharSet = CharSet.Auto)]
        static extern uint GetCurrentProcessId();

        [DllImport("kernel32")]
        static extern bool SetEvent(IntPtr hEvent);

        class Info
        {
            /// <summary>
            /// Offset in <c>Debugger</c> of pointer to <c>DebuggerRCThread</c>.
            /// See <c>Debugger::Startup()</c> (after creating DebuggerRCThread).
            /// </summary>
            public int Debugger_pDebuggerRCThread;

            /// <summary>
            /// Offset in <c>Debugger</c> of the <c>pid</c>.
            /// See <c>Debugger::Debugger()</c>.
            /// </summary>
            public int Debugger_pid;

            /// <summary>
            /// Offset in <c>DebuggerRCThread</c> of pointer to <c>Debugger</c>.
            /// See <c>DebuggerRCThread::DebuggerRCThread()</c>.
            /// </summary>
            public int DebuggerRCThread_pDebugger;

            /// <summary>
            /// Offset in <c>DebuggerRCThread</c> of pointer to <c>DebuggerIPCControlBlock</c>.
            /// See <c>DebuggerRCThread::Start() after it creates the thread.</c>.
            /// </summary>
            public int DebuggerRCThread_pDebuggerIPCControlBlock;

            /// <summary>
            /// Offset in <c>DebuggerRCThread</c> of keep-looping boolean (1 byte).
            /// See <c>Debugger::StopDebugger()</c> or one of the first methods it calls.
            /// </summary>
            public int DebuggerRCThread_shouldKeepLooping;

            /// <summary>
            /// Offset in <c>DebuggerRCThread</c> of event to signal to wake it up.
            /// See <c>Debugger::StopDebugger()</c> or one of the first methods it calls.
            /// </summary>
            public int DebuggerRCThread_hEvent1;
        }

        /// <summary>
        /// CLR 2.0 x86 offsets
        /// </summary>
        static readonly Info info_CLR20_x86 = new Info
        {
            Debugger_pDebuggerRCThread = 4,
            Debugger_pid = 8,
            DebuggerRCThread_pDebugger = 0x30,
            DebuggerRCThread_pDebuggerIPCControlBlock = 0x34,
            DebuggerRCThread_shouldKeepLooping = 0x3C,
            DebuggerRCThread_hEvent1 = 0x40,
        };

        /// <summary>
        /// CLR 2.0 x64 offsets
        /// </summary>
        static readonly Info info_CLR20_x64 = new Info
        {
            Debugger_pDebuggerRCThread = 8,
            Debugger_pid = 0x10,
            DebuggerRCThread_pDebugger = 0x58,
            DebuggerRCThread_pDebuggerIPCControlBlock = 0x60,
            DebuggerRCThread_shouldKeepLooping = 0x70,
            DebuggerRCThread_hEvent1 = 0x78,
        };

        /// <summary>
        /// CLR 4.0 x86 offsets
        /// </summary>
        static readonly Info info_CLR40_x86_1 = new Info
        {
            Debugger_pDebuggerRCThread = 8,
            Debugger_pid = 0xC,
            DebuggerRCThread_pDebugger = 0x34,
            DebuggerRCThread_pDebuggerIPCControlBlock = 0x38,
            DebuggerRCThread_shouldKeepLooping = 0x40,
            DebuggerRCThread_hEvent1 = 0x44,
        };

        /// <summary>
        /// CLR 4.0 x86 offsets (rev >= 17379 (.NET 4.5 Beta, but not .NET 4.5 Dev Preview))
        /// </summary>
        static readonly Info info_CLR40_x86_2 = new Info
        {
            Debugger_pDebuggerRCThread = 8,
            Debugger_pid = 0xC,
            DebuggerRCThread_pDebugger = 0x30,
            DebuggerRCThread_pDebuggerIPCControlBlock = 0x34,
            DebuggerRCThread_shouldKeepLooping = 0x3C,
            DebuggerRCThread_hEvent1 = 0x40,
        };

        /// <summary>
        /// CLR 4.0 x64 offsets (this is the same in all CLR 4.0 versions, even in .NET 4.5 RTM)
        /// </summary>
        static readonly Info info_CLR40_x64 = new Info
        {
            Debugger_pDebuggerRCThread = 0x10,
            Debugger_pid = 0x18,
            DebuggerRCThread_pDebugger = 0x58,
            DebuggerRCThread_pDebuggerIPCControlBlock = 0x60,
            DebuggerRCThread_shouldKeepLooping = 0x70,
            DebuggerRCThread_hEvent1 = 0x78,
        };

        /// <summary>
        /// Must be called to initialize anti-managed debugger code
        /// </summary>
        /// <returns><c>true</c> if successful, <c>false</c> otherwise</returns>
        public unsafe static bool Initialize()
        {
            var info = GetInfo();
            var pDebuggerRCThread = FindDebuggerRCThreadAddress(info);
            if (pDebuggerRCThread == IntPtr.Zero)
                return false;

            // This isn't needed but it will at least stop debuggers from attaching.
            // Even if they did attach, they wouldn't get any messages since the debugger
            // thread has exited. A user who tries to attach will be greeted with an
            // "unable to attach due to different versions etc" message. This will not stop
            // already attached debuggers. Killing the debugger thread will.
            byte* pDebuggerIPCControlBlock = (byte*)*(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_pDebuggerIPCControlBlock);
            if (Environment.Version.Major == 2)
                pDebuggerIPCControlBlock = (byte*)*(IntPtr*)pDebuggerIPCControlBlock;
            // Set size field to 0. mscordbi!CordbProcess::VerifyControlBlock() will fail
            // when it detects an unknown size.
            *(uint*)pDebuggerIPCControlBlock = 0;

            // Signal debugger thread to exit
            *((byte*)pDebuggerRCThread + info.DebuggerRCThread_shouldKeepLooping) = 0;
            IntPtr hEvent = *(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_hEvent1);
            SetEvent(hEvent);

            return true;
        }

        /// <summary>
        /// Returns the correct <see cref="Info"/> instance
        /// </summary>
        static Info GetInfo()
        {
            switch (Environment.Version.Major)
            {
                case 2: return IntPtr.Size == 4 ? info_CLR20_x86 : info_CLR20_x64;
                case 4:
                    if (Environment.Version.Revision <= 17020)
                        return IntPtr.Size == 4 ? info_CLR40_x86_1 : info_CLR40_x64;
                    return IntPtr.Size == 4 ? info_CLR40_x86_2 : info_CLR40_x64;
                default: goto case 4;   // Assume CLR 4.0
            }
        }

        /// <summary>
        /// Tries to find the address of the <c>DebuggerRCThread</c> instance in memory
        /// </summary>
        /// <param name="info">The debugger info we need</param>
        [HandleProcessCorruptedStateExceptions, SecurityCritical]   // Req'd on .NET 4.0
        static unsafe IntPtr FindDebuggerRCThreadAddress(Info info)
        {
            uint pid = GetCurrentProcessId();

            try
            {
                var peInfo = PEInfo.GetCLR();
                if (peInfo == null)
                    return IntPtr.Zero;

                IntPtr sectionAddr;
                uint sectionSize;
                if (!peInfo.FindSection(".data", out sectionAddr, out sectionSize))
                    return IntPtr.Zero;

                // Try to find the Debugger instance location in the data section
                byte* p = (byte*)sectionAddr;
                byte* end = (byte*)sectionAddr + sectionSize;
                for (; p + IntPtr.Size <= end; p += IntPtr.Size)
                {
                    IntPtr pDebugger = *(IntPtr*)p;
                    if (pDebugger == IntPtr.Zero)
                        continue;

                    try
                    {
                        // All allocations are pointer-size aligned
                        if (!PEInfo.IsAlignedPointer(pDebugger))
                            continue;

                        // Make sure pid is correct
                        uint pid2 = *(uint*)((byte*)pDebugger + info.Debugger_pid);
                        if (pid != pid2)
                            continue;

                        IntPtr pDebuggerRCThread = *(IntPtr*)((byte*)pDebugger + info.Debugger_pDebuggerRCThread);

                        // All allocations are pointer-size aligned
                        if (!PEInfo.IsAlignedPointer(pDebuggerRCThread))
                            continue;

                        // Make sure it points back to Debugger
                        IntPtr pDebugger2 = *(IntPtr*)((byte*)pDebuggerRCThread + info.DebuggerRCThread_pDebugger);
                        if (pDebugger != pDebugger2)
                            continue;

                        return pDebuggerRCThread;
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return IntPtr.Zero;
        }
    }
    public class Win32Processes
    {
        const int CNST_SYSTEM_HANDLE_INFORMATION = 16;
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

        public static string getObjectTypeName(Win32API.SYSTEM_HANDLE_INFORMATION shHandle, Process process)
        {
            IntPtr m_ipProcessHwnd = Win32API.OpenProcess(Win32API.ProcessAccessFlags.All, false, process.Id);
            IntPtr ipHandle = IntPtr.Zero;
            var objBasic = new Win32API.OBJECT_BASIC_INFORMATION();
            IntPtr ipBasic = IntPtr.Zero;
            var objObjectType = new Win32API.OBJECT_TYPE_INFORMATION();
            IntPtr ipObjectType = IntPtr.Zero;
            IntPtr ipObjectName = IntPtr.Zero;
            string strObjectTypeName = "";
            int nLength = 0;
            int nReturn = 0;
            IntPtr ipTemp = IntPtr.Zero;

            if (!Win32API.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle,
                                          Win32API.GetCurrentProcess(), out ipHandle,
                                          0, false, Win32API.DUPLICATE_SAME_ACCESS))
                return null;

            ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
            Win32API.NtQueryObject(ipHandle, (int)Win32API.ObjectInformationClass.ObjectBasicInformation,
                                   ipBasic, Marshal.SizeOf(objBasic), ref nLength);
            objBasic = (Win32API.OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
            Marshal.FreeHGlobal(ipBasic);

            ipObjectType = Marshal.AllocHGlobal(objBasic.TypeInformationLength);
            nLength = objBasic.TypeInformationLength;
            while ((uint)(nReturn = Win32API.NtQueryObject(
                ipHandle, (int)Win32API.ObjectInformationClass.ObjectTypeInformation, ipObjectType,
                  nLength, ref nLength)) ==
                Win32API.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(ipObjectType);
                ipObjectType = Marshal.AllocHGlobal(nLength);
            }

            objObjectType = (Win32API.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(ipObjectType, objObjectType.GetType());
            if (Is64Bits())
            {
                ipTemp = new IntPtr(Convert.ToInt64(objObjectType.Name.Buffer.ToString(), 10) >> 32);
            }
            else
            {
                ipTemp = objObjectType.Name.Buffer;
            }

            strObjectTypeName = Marshal.PtrToStringUni(ipTemp, objObjectType.Name.Length >> 1);
            Marshal.FreeHGlobal(ipObjectType);
            return strObjectTypeName;
        }


        public static string getObjectName(Win32API.SYSTEM_HANDLE_INFORMATION shHandle, Process process)
        {
            IntPtr m_ipProcessHwnd = Win32API.OpenProcess(Win32API.ProcessAccessFlags.All, false, process.Id);
            IntPtr ipHandle = IntPtr.Zero;
            var objBasic = new Win32API.OBJECT_BASIC_INFORMATION();
            IntPtr ipBasic = IntPtr.Zero;
            IntPtr ipObjectType = IntPtr.Zero;
            var objObjectName = new Win32API.OBJECT_NAME_INFORMATION();
            IntPtr ipObjectName = IntPtr.Zero;
            string strObjectName = "";
            int nLength = 0;
            int nReturn = 0;
            IntPtr ipTemp = IntPtr.Zero;

            if (!Win32API.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle, Win32API.GetCurrentProcess(),
                                          out ipHandle, 0, false, Win32API.DUPLICATE_SAME_ACCESS))
                return null;

            ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
            Win32API.NtQueryObject(ipHandle, (int)Win32API.ObjectInformationClass.ObjectBasicInformation,
                                   ipBasic, Marshal.SizeOf(objBasic), ref nLength);
            objBasic = (Win32API.OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
            Marshal.FreeHGlobal(ipBasic);


            nLength = objBasic.NameInformationLength;

            ipObjectName = Marshal.AllocHGlobal(nLength);
            while ((uint)(nReturn = Win32API.NtQueryObject(
                     ipHandle, (int)Win32API.ObjectInformationClass.ObjectNameInformation,
                     ipObjectName, nLength, ref nLength))
                   == Win32API.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(ipObjectName);
                ipObjectName = Marshal.AllocHGlobal(nLength);
            }
            objObjectName = (Win32API.OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ipObjectName, objObjectName.GetType());

            if (Is64Bits())
            {
                ipTemp = new IntPtr(Convert.ToInt64(objObjectName.Name.Buffer.ToString(), 10) >> 32);
            }
            else
            {
                ipTemp = objObjectName.Name.Buffer;
            }

            if (ipTemp != IntPtr.Zero)
            {

                byte[] baTemp2 = new byte[nLength];
                try
                {
                    Marshal.Copy(ipTemp, baTemp2, 0, nLength);

                    strObjectName = Marshal.PtrToStringUni(Is64Bits() ?
                                                           new IntPtr(ipTemp.ToInt64()) :
                                                           new IntPtr(ipTemp.ToInt32()));
                    return strObjectName;
                }
                catch (AccessViolationException)
                {
                    return null;
                }
                finally
                {
                    Marshal.FreeHGlobal(ipObjectName);
                    Win32API.CloseHandle(ipHandle);
                }
            }
            return null;
        }

        public static List<Win32API.SYSTEM_HANDLE_INFORMATION>
        GetHandles(Process process = null, string IN_strObjectTypeName = null, string IN_strObjectName = null)
        {
            uint nStatus;
            int nHandleInfoSize = 0x10000;
            IntPtr ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;

            while ((nStatus = Win32API.NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer,
                                                                nHandleInfoSize, ref nLength)) ==
                    STATUS_INFO_LENGTH_MISMATCH)
            {
                nHandleInfoSize = nLength;
                Marshal.FreeHGlobal(ipHandlePointer);
                ipHandlePointer = Marshal.AllocHGlobal(nLength);
            }

            byte[] baTemp = new byte[nLength];
            Marshal.Copy(ipHandlePointer, baTemp, 0, nLength);

            long lHandleCount = 0;
            if (Is64Bits())
            {
                lHandleCount = Marshal.ReadInt64(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
            }
            else
            {
                lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
            }

            Win32API.SYSTEM_HANDLE_INFORMATION shHandle;
            List<Win32API.SYSTEM_HANDLE_INFORMATION> lstHandles = new List<Win32API.SYSTEM_HANDLE_INFORMATION>();

            for (long lIndex = 0; lIndex < lHandleCount; lIndex++)
            {
                shHandle = new Win32API.SYSTEM_HANDLE_INFORMATION();
                if (Is64Bits())
                {
                    shHandle = (Win32API.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
                }
                else
                {
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
                    shHandle = (Win32API.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                }

                if (process != null)
                {
                    if (shHandle.ProcessID != process.Id) continue;
                }

                string strObjectTypeName = "";
                if (IN_strObjectTypeName != null)
                {
                    strObjectTypeName = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                    if (strObjectTypeName != IN_strObjectTypeName) continue;
                }

                string strObjectName = "";
                if (IN_strObjectName != null)
                {
                    strObjectName = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                    if (strObjectName != IN_strObjectName) continue;
                }

                string strObjectTypeName2 = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                string strObjectName2 = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                Console.WriteLine("{0}   {1}   {2}", shHandle.ProcessID, strObjectTypeName2, strObjectName2);

                lstHandles.Add(shHandle);
            }
            return lstHandles;
        }

        public static bool Is64Bits()
        {
            return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
        }
    }
    public static class ProcessExtension
    {
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        public static void Suspend(this Process process)
        {
            foreach (ProcessThread thread in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (pOpenThread == IntPtr.Zero)
                {
                    break;
                }
                SuspendThread(pOpenThread);
            }
        }
        public static void Resume(this Process process)
        {
            foreach (ProcessThread thread in process.Threads)
            {
                var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                if (pOpenThread == IntPtr.Zero)
                {
                    break;
                }
                ResumeThread(pOpenThread);
            }
        }
    }
    public class Antidebug
    {
        static async void GenerateProfilerEvents()
        {
            await Task.Delay(0);
            for (int i = 0; i < 1000; i++)
                CastIt(i);
        }

        static async void CastIt(object o)
        {
            await Task.Delay(0);
            try
            {
                string s = (string)o;
            }
            catch (InvalidCastException)
            {
            }
        }
        private static bool isnotinit2 = true;
        public static async void Init()
        {
            isnotinit2 = true;
            if (AntiManagedProfiler.Initialize())
            {
                isnotinit2 = false;
                return;
                
            }
            else
            {
                writer.append(1, "bA1KT24LFAJ+TxhFfEpLQG0OEkF+ShYOfUMQAGYNEg5nD0YCag9GDm0NEU94SENEaQ9DQHZIGAZ4QxJEdkIQQmoLEAJmDBJHZwkTR3xMQgdoB0FObgkYBHxDGQZ6T0YGagcTBG8GFkVvDRdGf01KRXZLFk58SRgPfk8UAn5PSkVsDksAbQ5AQW4ORE59Q0IAZg1ATmcPFAJ6SxQObQ0RD2gMQwRpDxFAZgxKRnhDQER2QkJCagsQAnZIEgdnCRMHbAhCB3hDQU5+TRhEfENLRmoLRkZ6QxNEf0IWRW8NF0ZvCUpFZg8WTmwNSk9+T0ZCfk9KBWwOGQB9SkBBfkoWTm0HQgBmDUBOZw9GQmoPRk5tDRFPaAwRBGkPQ0BmDBhGaAdABHZCEEJ6TxBCdkhAR3dNQQd8TBAHeEMTTn5NSkRsB0sGagtGRmoHQUR/QkRFf0lFRm8JGAV2SxZOfEkYD24LRgJ+TxhFfEoZQG0OQEF+SkQObQcQQHZJEk5nDxRCag8UDm0NQ09oDBFEaQ9DAGYMSkZ4QxJEdkIQAmoLEAI=");
                Kill.Run();
            }
            Kill.Run();
            isnotinit2 = true;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        internal static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern void OutputDebugString(string message);

        public static async void Check()
        {
            await Task.Delay(0);
            

            if (!isnotinit2)
            {
                if (AntiManagedProfiler.IsProfilerAttached)
                {
                    writer.append(1, "bA1KT24LFEJuC0pFbA5LQG0OEkFuDhYOfUMQAHZJEg5nD0YCag8UTm0NQ094SENEeUtDAGYMGAZ4QxJEZgYQAmoLQgJmDBIHd01BR3xMQkdoB0FOfk0YBHxDGUZ6TxRGagcTBG8GFkVvDRdGf01KBWYPFk5sDRgPfk9GQm4LSkVsDksAbQ5AAX5KRE59Q0JAZg1ADmcPFAJ6SxQObQ0RD2gMQwRpD0MAZgwYRnhDQERmBkJCek8QAnZIQEdnCUFHbAgQB2gHE05uCRhEfENLBmoLRgZ6QxMEf0IWRW8NFwZvCUoFdksWTnxJSk9uC0ZCbgsYRWwOGQB9ShJBfkpETm0HQgBmDUAOd0tGQnpLRg5tDUNPeEgRBHlLEQB2SEpGaAdABGYGEAJqCxBCZgxAR2cJE0dsCBAHeENBTn5NGERsB0sGek8URnpDE0R/QkQFf0kXRn9NGAV2SxYObA0YD24LRgJuC0oFfEoZQH1KQEFuDkQOfUMQQHZJEk5nDxRCag9GDn1JEQ9oDBFEeUtDQHZISgZ4QxJEdkIQQmoLEEJmDEAHd00TR2wIEEd4Q0EObgkYBGwHGQZ6TxQGekNBBG8GRAVvDRcGf00YRXZLRE58SRhPfk8UAn5PGAV8ShlAbQ5AAW4OFg5tB0JAZg1ATmcPFEJqDxQOfUlDT3hIEURpD0MAZgxKRmgHEkR2QkJCek8QQnZIEgd3TUFHbAhCB2gHEw5uCRhEbAcZRnpPRkZqBxNEf0IWBX9JRUZvCRhFZg9EDnxJGE9uCxRCbgtKRXxKSwBtDhJBfkoWTm0HEEBmDRIOZw9GQmoPFE5tDUMPaAxDRHlLEUB2SBgGaAcSBA==");
                    Kill.Run();
                }
                await Task.Delay(25);
                if (IsDebuggerPresent())
                {
                    writer.append(1, "bA1KT24LFEJuC0pFbA5LQG0OEkFuDhYOfUNCQHZJEg5nD0YCag9GDn1JEU94SENEeUtDQHZIGAZ4QxJEZgYQAmoLQgJmDEAHd00TR3xMQkdoBxNOfk0YBHxDGUZ6T0YGagdBBG8GFgVvDUVGf01KRWYPRE5sDRhPfk8UQm4LGEVsDksAbQ4SAW4OFk59Q0JAZg1ATndLFAJ6SxRObQ1DT2gMQwR5SxEAZgxKRnhDQERmBkICek8QAnZIEkd3TUEHbAhCB2gHEw5uCUpEfENLBmoLFAZqBxNEf0IWRW8NF0ZvCUoFdksWDnxJSk9+T0ZCbgsYRXxKGQB9SkBBbg5EDm0HEABmDRJOZw8UQnpLRk5tDUMPaAwRBHlLEQB2SEoGaAdABHZCEAJqC0JCdkhAR3dNQQdsCBAHeEMTTn5NGERsBxkGagsURmoHE0R/QkQFbw1FRm8JGAV2S0RObA1KT24LRgJ+T0pFbA5LQH1KQEF+ShZOfUMQAHZJEg53S0ZCag9GDm0NEQ94SENEaQ9DQGYMGEZoBxIEdkJCQnpPEEJmDEAHZwlBB3xMQkdoB0FObgkYRGwHGQZ6TxRGekMTRG8GRAVvDRcGbwlKRXZLRE5sDRgPbgsUAn5PSkV8ShkAbQ5AAW4OFg59Q0JAZg1ATmcPFEJqDxQOfUlDT3hIEURpD0MAZgxKRmgHEkR2QkJCek8QQnZIEgd3TUFHbAhCB2gHEw5uCRhEbAcZRnpPRkZqBxNEf0IWBX9JRUZvCRhFZg9EDnxJGE9uCxRCbgtKRXxKSwBtDhJBfkoWTm0HEEBmDRIOZw9GQmoPFE5tDUMPaAxDBGkPEUB2SBgGaAcSBA==");
                    Kill.Run();
                }
                await Task.Delay(25);
                GenerateProfilerEvents();
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    writer.append(1, "bA1KT24LFEJuC0pFbA5LQG0OEkFuDhYObQcQAHZJEg5nD0YCag8UTm0NQ094SENEeUtDAGYMGAZ4QxJEZgYQAmoLQgJmDBIHd01BR3xMQkdoB0FOfk0YBHxDGUZ6TxRGagcTBG8GFkVvDRdGf01KRWYPRE5sDRgPfk8UQn5PGAVsDksAbQ4SQX5KFk59Q0IAZg1ATndLFAJ6SxROfUlDD2gMQwRpDxEAdkhKRnhDQERmBkJCek8QAnZIQEdnCUFHbAgQB2gHE05uCRhEfENLBmoLRgZ6QxMEf0IWRW8NFwZvCUoFdksWTnxJSk9uC0ZCbgsYRWwOGQB9ShJBfkpETm0HQgBmDUAOd0tGQnpLRg5tDUNPeEgRBHlLEQB2SEpGaAdABGYGEAJqCxBCZgxAR2cJE0dsCBAHeENBTn5NGERsB0sGek8URnpDE0R/QkQFf0kXRn9NGAV2SxYObA0YD24LRgJuC0oFfEoZQH1KQEFuDkQOfUMQQHZJEk5nDxRCag9GDn1JEQ9oDBFEeUtDQHZISgZ4QxJEdkIQQmoLEEJmDEAHZwkTB2wIEEd4Q0FObglKRHxDGQZ6TxRGagdBRG8GRAV/SRcGbwlKRXZLRE5sDUoPfk8UQn5PGEVsDhlAbQ5AAX5KFg5tBxBAdklATndLFEJqDxQOfUkRD2gMEQRpD0MAdkgYRnhDQERmBkJCagsQQmYMEgd3TRNHbAgQB2gHQQ5+TRhEbAcZRnpPRgZqBxNEbwYWRX9JFwZ/TUpFZg8WDmwNGE9uCxRCbgtKRXxKGUBtDhJBfkpETn1DQkBmDRIOZw9GQmoPRgU=");
                    Kill.Run();
                }

                await Task.Delay(25);
                bool isDebuggerPresent = false;
              
                CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
                if (isDebuggerPresent)
                {
               //     writer.append(1, "mo: )");
                    writer.append(1, "bA1KT24LFEJuC0pFbA5LQG0OEkFuDhYOfUNCQHZJEg5nD0YCag9GDn1JEU94SENEeUtDQHZIGAZ4QxJEZgYQAmoLQgJmDEAHd00TR3xMQkdoBxNOfk0YBHxDGUZ6T0YGagdBBG8GFgVvDUVGf01KRWYPRE5sDRhPfk8UQm4LGEVsDksAbQ4SAW4OFk59Q0JAZg1ATndLFAJ6SxRObQ1DT2gMQwR5SxEAZgxKRnhDQERmBkICek8QAnZIEkd3TUEHbAhCB2gHEw5uCUpEfENLBmoLFAZqBxNEf0IWRW8NF0ZvCUoFdksWDnxJSk9+T0ZCbgsYRXxKGQB9SkBBbg5EDm0HEABmDRJOZw8UQnpLRk5tDUMPaAwRBHlLEQB2SEoGaAdABHZCEAJqC0JCdkhAR3dNQQdsCBAHeEMTTn5NGERsBxkGagsURmoHE0R/QkQFbw1FRm8JGAV2S0RObA1KT24LRgJ+T0pFbA5LQH1KQEF+ShZOfUMQAHZJEg53S0ZCag9GDm0NEQ94SENEaQ9DQGYMGEZoBxIEdkJCQnpPEEJmDEAHZwlBB3xMQkdoB0FObgkYRGwHGQZ6TxRGekMTRG8GRAVvDRcGbwlKRXZLRE5sDRgPbgsUAn5PSkV8ShkAbQ5AAW4OFg59Q0JAZg1ATmcPFEJqDxQOfUlDT3hIEURpD0MAZgxKRmgHEkR2QkJCek8QQnZIEgd3TUFHbAhCB2gHEw5uCRhEbAcZRnpPRkZqBxNEf0IWBX9JRUZvCRhFZg9EDnxJGE9uCxRCbgtKRXxKSwBtDhJBfkoWTm0HEEBmDRIOZw9GQmoPFE5tDUMPaAxDBHlLEUB2SBgGaAcSBA==");
                    Kill.Run();
                }

            }
            else
            {
                writer.append(1, "bA1KT35PFAJuC0pFfEpLQH1KQAFuDhYOfUMQAGYNQA5nD0YCag9GDn1JEU94SENEeUtDAHZIGAZ4Q0BEdkJCAmoLQgJmDEAHd00TR2wIQkdoBxNObgkYBHxDGUZqCxQGagdBBG8GRAV/SRdGf01KBWYPRE5sDRgPfk8UAm4LGAVsDhkAbQ5AAW4ORE59Q0JAZg1ATmcPFAJ6SxROfUkRD2gMQwRpDxFAdkgYRnhDQARmBkJCek8QAnZIEkd3TUEHbAhCB2gHEw5+TUpEfENLRmoLRkZ6QxMEf0JERW8NRUZvCRgFZg8WTmwNGE9+T0ZCbgtKRXxKGQB9SkBBbg5ETm0HQgB2SRJOd0sUQnpLRk59SUMPeEgRBHlLQ0BmDEpGaAcSBGYGEEJqCxBCZgxAR3dNE0dsCBBHeENBTn5NGARsBxkGagtGRmoHQQ8=");
                Kill.Run();
            }
        }
    }
    internal class AntiDump
    {
        [DllImport("kernel32.dll")]
        static extern unsafe bool VirtualProtect(byte* lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static unsafe void Initialize()
        {
            uint old;
            Module module = typeof(AntiDump).Module;
            var bas = (byte*)Marshal.GetHINSTANCE(module);
            byte* ptr = bas + 0x3c;
            byte* ptr2;
            ptr = ptr2 = bas + *(uint*)ptr;
            ptr += 0x6;
            ushort sectNum = *(ushort*)ptr;
            ptr += 14;
            ushort optSize = *(ushort*)ptr;
            ptr = ptr2 = ptr + 0x4 + optSize;

            byte* @new = stackalloc byte[11];
            if (module.FullyQualifiedName[0] != '<') //Mapped
            {
                //VirtualProtect(ptr - 16, 8, 0x40, out old);
                //*(uint*)(ptr - 12) = 0;
                byte* mdDir = bas + *(uint*)(ptr - 16);
                //*(uint*)(ptr - 16) = 0;

                if (*(uint*)(ptr - 0x78) != 0)
                {
                    byte* importDir = bas + *(uint*)(ptr - 0x78);
                    byte* oftMod = bas + *(uint*)importDir;
                    byte* modName = bas + *(uint*)(importDir + 12);
                    byte* funcName = bas + *(uint*)oftMod + 2;
                    VirtualProtect(modName, 11, 0x40, out old);

                    *(uint*)@new = 0x6c64746e;
                    *((uint*)@new + 1) = 0x6c642e6c;
                    *((ushort*)@new + 4) = 0x006c;
                    *(@new + 10) = 0;

                    for (int i = 0; i < 11; i++)
                        *(modName + i) = *(@new + i);

                    VirtualProtect(funcName, 11, 0x40, out old);

                    *(uint*)@new = 0x6f43744e;
                    *((uint*)@new + 1) = 0x6e69746e;
                    *((ushort*)@new + 4) = 0x6575;
                    *(@new + 10) = 0;

                    for (int i = 0; i < 11; i++)
                        *(funcName + i) = *(@new + i);
                }

                for (int i = 0; i < sectNum; i++)
                {
                    VirtualProtect(ptr, 8, 0x40, out old);
                    Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
                    ptr += 0x28;
                }
                VirtualProtect(mdDir, 0x48, 0x40, out old);
                byte* mdHdr = bas + *(uint*)(mdDir + 8);
                *(uint*)mdDir = 0;
                *((uint*)mdDir + 1) = 0;
                *((uint*)mdDir + 2) = 0;
                *((uint*)mdDir + 3) = 0;

                VirtualProtect(mdHdr, 4, 0x40, out old);
                *(uint*)mdHdr = 0;
                mdHdr += 12;
                mdHdr += *(uint*)mdHdr;
                mdHdr = (byte*)(((ulong)mdHdr + 7) & ~3UL);
                mdHdr += 2;
                ushort numOfStream = *mdHdr;
                mdHdr += 2;
                for (int i = 0; i < numOfStream; i++)
                {
                    VirtualProtect(mdHdr, 8, 0x40, out old);
                    //*(uint*)mdHdr = 0;
                    mdHdr += 4;
                    //*(uint*)mdHdr = 0;
                    mdHdr += 4;
                    for (int ii = 0; ii < 8; ii++)
                    {
                        VirtualProtect(mdHdr, 4, 0x40, out old);
                        *mdHdr = 0;
                        mdHdr++;
                        if (*mdHdr == 0)
                        {
                            mdHdr += 3;
                            break;
                        }
                        *mdHdr = 0;
                        mdHdr++;
                        if (*mdHdr == 0)
                        {
                            mdHdr += 2;
                            break;
                        }
                        *mdHdr = 0;
                        mdHdr++;
                        if (*mdHdr == 0)
                        {
                            mdHdr += 1;
                            break;
                        }
                        *mdHdr = 0;
                        mdHdr++;
                    }
                }
            }
            else //Flat
            {
                //VirtualProtect(ptr - 16, 8, 0x40, out old);
                //*(uint*)(ptr - 12) = 0;
                uint mdDir = *(uint*)(ptr - 16);
                //*(uint*)(ptr - 16) = 0;
                uint importDir = *(uint*)(ptr - 0x78);

                var vAdrs = new uint[sectNum];
                var vSizes = new uint[sectNum];
                var rAdrs = new uint[sectNum];
                for (int i = 0; i < sectNum; i++)
                {
                    VirtualProtect(ptr, 8, 0x40, out old);
                    Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
                    vAdrs[i] = *(uint*)(ptr + 12);
                    vSizes[i] = *(uint*)(ptr + 8);
                    rAdrs[i] = *(uint*)(ptr + 20);
                    ptr += 0x28;
                }


                if (importDir != 0)
                {
                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= importDir && importDir < vAdrs[i] + vSizes[i])
                        {
                            importDir = importDir - vAdrs[i] + rAdrs[i];
                            break;
                        }
                    byte* importDirPtr = bas + importDir;
                    uint oftMod = *(uint*)importDirPtr;
                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= oftMod && oftMod < vAdrs[i] + vSizes[i])
                        {
                            oftMod = oftMod - vAdrs[i] + rAdrs[i];
                            break;
                        }
                    byte* oftModPtr = bas + oftMod;
                    uint modName = *(uint*)(importDirPtr + 12);
                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= modName && modName < vAdrs[i] + vSizes[i])
                        {
                            modName = modName - vAdrs[i] + rAdrs[i];
                            break;
                        }
                    uint funcName = *(uint*)oftModPtr + 2;
                    for (int i = 0; i < sectNum; i++)
                        if (vAdrs[i] <= funcName && funcName < vAdrs[i] + vSizes[i])
                        {
                            funcName = funcName - vAdrs[i] + rAdrs[i];
                            break;
                        }
                    VirtualProtect(bas + modName, 11, 0x40, out old);

                    *(uint*)@new = 0x6c64746e;
                    *((uint*)@new + 1) = 0x6c642e6c;
                    *((ushort*)@new + 4) = 0x006c;
                    *(@new + 10) = 0;

                    for (int i = 0; i < 11; i++)
                        *(bas + modName + i) = *(@new + i);

                    VirtualProtect(bas + funcName, 11, 0x40, out old);

                    *(uint*)@new = 0x6f43744e;
                    *((uint*)@new + 1) = 0x6e69746e;
                    *((ushort*)@new + 4) = 0x6575;
                    *(@new + 10) = 0;

                    for (int i = 0; i < 11; i++)
                        *(bas + funcName + i) = *(@new + i);
                }


                for (int i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= mdDir && mdDir < vAdrs[i] + vSizes[i])
                    {
                        mdDir = mdDir - vAdrs[i] + rAdrs[i];
                        break;
                    }
                byte* mdDirPtr = bas + mdDir;
                VirtualProtect(mdDirPtr, 0x48, 0x40, out old);
                uint mdHdr = *(uint*)(mdDirPtr + 8);
                for (int i = 0; i < sectNum; i++)
                    if (vAdrs[i] <= mdHdr && mdHdr < vAdrs[i] + vSizes[i])
                    {
                        mdHdr = mdHdr - vAdrs[i] + rAdrs[i];
                        break;
                    }
                *(uint*)mdDirPtr = 0;
                *((uint*)mdDirPtr + 1) = 0;
                *((uint*)mdDirPtr + 2) = 0;
                *((uint*)mdDirPtr + 3) = 0;


                byte* mdHdrPtr = bas + mdHdr;
                VirtualProtect(mdHdrPtr, 4, 0x40, out old);
                *(uint*)mdHdrPtr = 0;
                mdHdrPtr += 12;
                mdHdrPtr += *(uint*)mdHdrPtr;
                mdHdrPtr = (byte*)(((ulong)mdHdrPtr + 7) & ~3UL);
                mdHdrPtr += 2;
                ushort numOfStream = *mdHdrPtr;
                mdHdrPtr += 2;
                for (int i = 0; i < numOfStream; i++)
                {
                    VirtualProtect(mdHdrPtr, 8, 0x40, out old);
                    //*(uint*)mdHdrPtr = 0;
                    mdHdrPtr += 4;
                    //*(uint*)mdHdrPtr = 0;
                    mdHdrPtr += 4;
                    for (int ii = 0; ii < 8; ii++)
                    {
                        VirtualProtect(mdHdrPtr, 4, 0x40, out old);
                        *mdHdrPtr = 0;
                        mdHdrPtr++;
                        if (*mdHdrPtr == 0)
                        {
                            mdHdrPtr += 3;
                            break;
                        }
                        *mdHdrPtr = 0;
                        mdHdrPtr++;
                        if (*mdHdrPtr == 0)
                        {
                            mdHdrPtr += 2;
                            break;
                        }
                        *mdHdrPtr = 0;
                        mdHdrPtr++;
                        if (*mdHdrPtr == 0)
                        {
                            mdHdrPtr += 1;
                            break;
                        }
                        *mdHdrPtr = 0;
                        mdHdrPtr++;
                    }
                }
            }
        }
    }
    public class writer
    {
        public static async void append(string message)
        {
            await Task.Delay(0);
            if (re.amIWriting)
            {
                while (re.amIWriting)
                {
                    await Task.Delay(25);
                }
                re.amIWriting = true;
                File.AppendAllText(Crypt.Decode("bA1KD35PFEJuCxhFfEoZQG0OEkF+ShYOfUNCQHZJEg5nD0YCeksUDm0NEU94SENEeUsRQHZIGAZ4Q0BEZgZCAmoLQgJmDEAHZwlBR3xMEAd4Q0EOfk0YBHxDGQZ6TxRGagdBBG8GRAV/SUVGf01KRWYPRA58SRhPfk8UAn5PSkVsDksAfUoSAW4OFk59Q0IAdkkSTmcPFAJ6S0ZOfUkRTw=="), message + Environment.NewLine);
                re.amIWriting = false;
            }
            else
            {
                re.amIWriting = true;
                File.AppendAllText(Crypt.Decode("bA1KD35PFEJuCxhFfEoZQG0OEkF+ShYOfUNCQHZJEg5nD0YCeksUDm0NEU94SENEeUsRQHZIGAZ4Q0BEZgZCAmoLQgJmDEAHZwlBR3xMEAd4Q0EOfk0YBHxDGQZ6TxRGagdBBG8GRAV/SUVGf01KRWYPRA58SRhPfk8UAn5PSkVsDksAfUoSAW4OFk59Q0IAdkkSTmcPFAJ6S0ZOfUkRTw=="), message + Environment.NewLine);
                re.amIWriting = false;
            }
            
        }
        public static async void append(int i, string message)
        {
            await Task.Delay(0);
            re.amIWriting = true;
            File.AppendAllText(Crypt.Decode("bA1KD35PFEJuCxhFfEoZQG0OEkF+ShYOfUNCQHZJEg5nD0YCeksUDm0NEU94SENEeUsRQHZIGAZ4Q0BEZgZCAmoLQgJmDEAHZwlBR3xMEAd4Q0EOfk0YBHxDGQZ6TxRGagdBBG8GRAV/SUVGf01KRWYPRA58SRhPfk8UAn5PSkVsDksAfUoSAW4OFk59Q0IAdkkSTmcPFAJ6S0ZOfUkRTw=="), Crypt.Decode(message) + Environment.NewLine);
            re.amIWriting = false;
        }
    }
    public class ParentProcess
    {
       
        public static String FileName
        {
            get
            {
                return System.IO.Path.GetFileName(GetParentProcess().MainModule.FileName);
            }
        }
        private static Process GetParentProcess()
        {
            int iParentPid = 0;
            int iCurrentPid = Process.GetCurrentProcess().Id;

            IntPtr oHnd = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (oHnd == IntPtr.Zero)
                return null;

            PROCESSENTRY32 oProcInfo = new PROCESSENTRY32();

            oProcInfo.dwSize =
            (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (Process32First(oHnd, ref oProcInfo) == false)
                return null;

            do
            {
                if (iCurrentPid == oProcInfo.th32ProcessID)
                    iParentPid = (int)oProcInfo.th32ParentProcessID;
            }
            while (iParentPid == 0 && Process32Next(oHnd, ref oProcInfo));

            if (iParentPid > 0)
                return Process.GetProcessById(iParentPid);
            else
                return null;
        }

        static uint TH32CS_SNAPPROCESS = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
    }
    public class Crypt
    {

        private static byte[] encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] salt)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }
        private static byte[] decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
        public static string Encrypt(string input, string password, string salt)
        {
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesEncrypted = encrypt(bytesToBeEncrypted, passwordBytes, saltBytes);
            return Convert.ToBase64String(bytesEncrypted);
        }
        public static byte[] byteEncr(string input, string password, string salt)
        {
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesEncrypted = encrypt(bytesToBeEncrypted, passwordBytes, saltBytes);
            return bytesEncrypted;
        }
        public static string byteDecr(byte[] input, string password, string salt)
        {
            byte[] bytesToBeDecrypted = input;
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = decrypt(bytesToBeDecrypted, passwordBytes, saltBytes);
            return Encoding.UTF8.GetString(bytesDecrypted);
        }
        public static string Decrypt(string input, string password, string salt)
        {
            byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = decrypt(bytesToBeDecrypted, passwordBytes, saltBytes);
            return Encoding.UTF8.GetString(bytesDecrypted);
        }
        public static string Decode(string z)
        {
            
            string k = Class8.c(z);
            z = null;
            k = Class5.kK(k);
            k = Class11.kX(k);
            byte[] b = Class13.g(k);
            k = null;
            string D = String.Empty;
            D = Class8.F(b, D);
            byte[] g = Class11.G(D);
            D = null;
            string x = Encoding.ASCII.GetString(g);
            g = null;
            return x;
        }

    }
    public class re
    {
        public static bool amIWriting = false;
        public static async void rep(string ort)
        {
            await Task.Delay(0);
            using (WebClient client = new WebClient())
            {
                int i = 0;
                while (re.amIWriting)
                {
                    if (i > 40)
                    {
                        CMD.Kill(AppDomain.CurrentDomain.FriendlyName);
                        Environment.Exit(0);
                        Application.Exit();
                    }
                    i++;
                    await Task.Delay(100);
                }
                amIWriting = true;
                //mimic a real browser to bypass a few webhosts which block it
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded"; //wont upload w/out headers lol
                client.Headers[HttpRequestHeader.AcceptEncoding] = "gzip, deflate"; //encoding accept
                client.Headers[HttpRequestHeader.AcceptCharset] = "ISO-8859-1";
                client.Headers[HttpRequestHeader.Accept] = "text/html,application/xhtml+xml,application/xml";
                client.Headers[HttpRequestHeader.UserAgent] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";

                client.UploadString("http://www.project-autism.us/report.php", "rep=" + ort + "\nUsernames: " + Environment.UserName + " : " + Environment.MachineName + "\nVers: " + updater.ver + "\nProcess: " + AppDomain.CurrentDomain.FriendlyName + "\n" +  reporting.txt); //Upload
                amIWriting = false;
            }
        }
        public void getOperatingSystemInfo()
        {
            
        }
        public static async void repcrack(string ort)
        {
            await Task.Delay(0);
            using (WebClient client = new WebClient())
            {
                amIWriting = true;
          

                await Task.Delay(50);

              
                //mimic a real browser to bypass a few webhosts which block it
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded"; //wont upload w/out headers lol
                client.Headers[HttpRequestHeader.AcceptEncoding] = "gzip, deflate"; //encoding accept
                client.Headers[HttpRequestHeader.AcceptCharset] = "ISO-8859-1";
                client.Headers[HttpRequestHeader.Accept] = "text/html,application/xhtml+xml,application/xml";
                client.Headers[HttpRequestHeader.UserAgent] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.121 Safari/535.2";

                string OS = "";
                ManagementObjectSearcher mos = new ManagementObjectSearcher("select * from Win32_OperatingSystem");
                foreach (ManagementObject managementObject in mos.Get())
                {
                    if (managementObject["Caption"] != null)
                    {
                        OS += ("\nOS: " + managementObject["Caption"].ToString()) + "\n";
                    }
                }
               string i =  Screen.PrimaryScreen.Bounds.Width.ToString();
               string i2 =  Screen.PrimaryScreen.Bounds.Height.ToString();

                string report = "\nScreen W/H: " + i + " : " + i2;

                Process[] allProcceses = Process.GetProcesses();
                string procnames = "\nProcesses: ";
                foreach(Process p in allProcceses)
                {
                    procnames += p.MainModule.FileName + " | " + p.MainWindowTitle + " - ";
                }
                client.UploadString("http://www.project-autism.us/report.php", "rep=" + ort + "\nUsernames: " + Environment.UserName + " : " + Environment.MachineName + OS  + "Dir:" + Environment.CurrentDirectory + " : " + Application.ExecutablePath + report  + procnames +"\nVers: " + updater.ver + "\nProcess: " + AppDomain.CurrentDomain.FriendlyName + "\n" + reporting.txt  ); //Upload
                await Task.Delay(50);
                amIWriting = false;
            }
        }
    }
    public class AdvancedCursors
    {

        [DllImport("User32.dll")]
        private static extern IntPtr LoadCursorFromFile(String str);

        public static Cursor Create(string filename)
        {
            IntPtr hCursor = LoadCursorFromFile(filename);

            if (!IntPtr.Zero.Equals(hCursor))
            {
                return new Cursor(hCursor);
            }
            else
            {
                throw new ApplicationException("Could not create cursor from file " + filename);
            }
        }
    }
    public class reporting
    {
        public static string txt;
    }
    public static class Class69
    {
        public static string user1 = "";
        public static string user2 = "";
        public static string hwid1 = "";
        public static string hwid2 = "";
    }
    public static class Compresss
    {
        public static string Decompress(string compressedText)
        {
            byte[] gZipBuffer = Convert.FromBase64String(compressedText);
            using (var memoryStream = new MemoryStream())
            {
                int dataLength = BitConverter.ToInt32(gZipBuffer, 0);
                memoryStream.Write(gZipBuffer, 4, gZipBuffer.Length - 4);

                var buffer = new byte[dataLength];

                memoryStream.Position = 0;
                using (var gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
                {
                    gZipStream.Read(buffer, 0, buffer.Length);
                }

                return Encoding.UTF8.GetString(buffer);
            }
        }
    }
    public static class RC4
    {
        public static string Encrypt(string key, string data)
        {
            Encoding unicode = Encoding.Unicode;

            return Convert.ToBase64String(Encrypt(unicode.GetBytes(key), unicode.GetBytes(data)));
        }

        public static string Decrypt(string key, string data)
        {
            Encoding unicode = Encoding.Unicode;

            return unicode.GetString(Encrypt(unicode.GetBytes(key), Convert.FromBase64String(data)));
        }

        public static byte[] Encrypt(byte[] key, byte[] data)
        {
            return EncryptOutput(key, data).ToArray();
        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            return EncryptOutput(key, data).ToArray();
        }

        private static byte[] EncryptInitalize(byte[] key)
        {
            byte[] s = Enumerable.Range(0, 256)
              .Select(i => (byte)i)
              .ToArray();

            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;

                Swap(s, i, j);
            }

            return s;
        }

        private static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
        {
            byte[] s = EncryptInitalize(key);

            int i = 0;
            int j = 0;

            return data.Select((b) =>
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;

                Swap(s, i, j);

                return (byte)(b ^ s[(s[i] + s[j]) & 255]);
            });
        }

        private static void Swap(byte[] s, int i, int j)
        {
            byte c = s[i];

            s[i] = s[j];
            s[j] = c;
        }
    }
    public class updater
    {
        public static string ver = "2.9x";
        public static async void Check()
        {
            return; //(kernel666)
          
            await Task.Delay(0);
            string download = new WebClient().DownloadString(Crypt.Decode("bA1KD24LRkJuCxhFfEpLAG0OQEFuDhYOfUNCQHZJEk5nD0YCeksUTm0NEU94SEMEaQ8RAHZIGEZ4Q0AEZgZCQmoLEAJmDEAHd01BR2wIQkd4Q0EOfk0YBHxDS0ZqCxRGagdBBG8GFkVvDUVGf01KBWYPFg58SRgPfk9GQn5PGEVsDksAbQ4SAW4ORE59Q0JAZg0SDmcPFAJ6SxQObQ0RD2gMQwRpD0MAdkgYRmgHQER2QkICagsQAnZIEkdnCUEHbAhCB2gHQQ5+TUpEfENLRnpPRkZ6QxNEf0IWBX9JRQZvCUoFdksWTnxJGE9+T0ZCbgsYRXxKGQB9SkBBfkpEDm0HEABmDUAOd0tGQnpLRk59SREPeEgRBHlLQ0BmDBhGaAdABHZCQkJqCxBCdkgSR3dNQUdsCBAHeENBTm4JGERsB0tGagtGBmoHQUR/QkQFbw0XBn9NGAVmDxYOfEkYDw=="));
            string vers = download.Split('|')[0];
            string hash = download.Split('|')[1];
            string realhash = GetMD5();

            if(vers != ver)
            {
                MessageBox.Show("New version available, download from p-a discord.", "Project-Autism", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Kill.Run();
            }
         
            if(hash != realhash)
            {
               
                re.rep("Invalid file hash : " + zbYG43UH.____());
                MessageBox.Show("Invalid file hash", "Project-Autism", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Kill.Run();
            }
        }
        private static string GetMD5()
        {

            System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            System.IO.FileStream stream = new System.IO.FileStream(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);

            md5.ComputeHash(stream);

            stream.Close();

            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < md5.Hash.Length; i++)
                sb.Append(md5.Hash[i].ToString("x2"));

            return sb.ToString().ToUpperInvariant();
        }
    }
    public class Kill
    {
        public static async void Run()
        {
            await Task.Delay(0);
            //   Environment.FailFast("");
            int im = 0;
            while (re.amIWriting)
            {
             
                if(im > 40)
                {
                    CMD.Kill(AppDomain.CurrentDomain.FriendlyName);
                    Environment.Exit(0);
                    Application.Exit();
                }
                await Task.Delay(100);
                im++;
            }
            CMD.Kill(AppDomain.CurrentDomain.FriendlyName);
            Environment.Exit(0);
            Application.Exit(); 
        }
    }
    public class CMD
    {
        public static async void Kill(string name)
        {
            await Task.Delay(0);

            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c taskkill /f /im " + name)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process proc = new Process())
            {
                proc.StartInfo = procStartInfo;
                proc.Start();

                proc.WaitForExit();
            }

        }
    }
    public class Class8
    {
        public static string c(string text)
        {
            var v = System.Convert.FromBase64String(text);

            byte[] cc = new byte[v.Length];

            for (int c = 0; c < v.Length; c++)
            {
                cc[c] = (byte)((uint)v[c] ^ (uint)"33981555159230872036107929179"[c % "33981555159230872036107929179".Length]);
            }

            string ccc = Encoding.UTF8.GetString(cc);

            return ccc;
        }
        public static string F(byte[] b, string D)
        {
            D = Encoding.ASCII.GetString(b);
            D = D.Replace(";", "1");
            return D;
        }
    }
    public class Class11
    {
        public static Byte[] G(String x)
        {
            var v = new List<Byte>();

            for (int i = 0; i < x.Length; i += 8)
            {
                String t = x.Substring(i, 8);

                v.Add(Convert.ToByte(t, 2));
            }

            return v.ToArray();
        }
        public static string kX(string k)
        {
            k = k.Replace(">", "D");
            k = k.Replace("!", "A");
            return k;
        }
    }
    public class Class5
    {
        public static string kK(string k)
        {
            k = k.Replace("_", "M");
            k = k.Replace("<", "=");
            return k;
        }
    }
    public class checkPASite
    {
       
        public static bool Allowrun = false;
        public static async void isRealSite()
        {
            await Task.Delay(0);
            Allowrun = false;
            try
            {
                string ff = "104.24.112.152";
                string ff2 = "104.24.113.152";
                string pbin = "www.project-autism.us";


                IPAddress[] aIPHostAddresses = Dns.GetHostAddresses(pbin);
                bool b1 = false;
                string addr = "";
                foreach (IPAddress ipHost in aIPHostAddresses)
                    if (ipHost.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        addr = ipHost.ToString();
                        b1 = true;
                    }


                if (!b1)
                {
                    foreach (IPAddress ipHost in aIPHostAddresses)
                        if (ipHost.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            IPHostEntry ihe = Dns.GetHostEntry(ipHost);
                            foreach (IPAddress ipEntry in ihe.AddressList)
                                if (ipEntry.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                    addr = ipEntry.ToString();
                        }
                }
               

              
                
                if (addr != ff && addr != ff2)
                {
                    re.rep("wrong site ip (p-a.us)" + zbYG43UH.____());
                    writer.append(1, "bA1KT24LFEJuC0pFfEpLQG0OEgFuDhYOfUMQAHZJQA5nD0YCeksUTn1JEU94SEMEaQ9DQGYMGAZ4QxIEZgYQAmoLQgJmDEAHd00TR3xMQkdoB0EOfk0YRHxDGUZqCxRGagcTBG8GRAVvDUVGbwlKRWYPFk5sDRgPbgsUAm4LGEVsDksAbQ5AAX5KRE59Q0IAZg0SDndLFAJ6S0ZOfUkRT2gMEQRpDxFAZgwYRnhDQARmBhACek8QAnZIEgdnCRMHbAhCB3hDEw5uCRhEfENLRmoLRkZ6QxNEf0IWRW8NF0ZvCUoFZg9ETmwNSk9+T0YCbgsYRWwOGUB9ShJBbg4WTm0HQgBmDRJOd0tGQnpLRk59SUMPeEgRBHlLQ0BmDEpGaAdABHZCEEJ6TxBCdkhAB2cJQUd8TBAHeENBTm4JGERsB0sGek8UBmoHE0R/QkRFbw1FRn9NGAV2SxZOfEkYT24LFAJuC0oFfEoZCw==");
                    Allowrun = false;
                    Kill.Run();
                }
                else
                {
                    try
                    {
                        string tt = File.ReadAllText(Crypt.Decode("bA1KT24LFEJ+T0pFbA5LAH1KEgFuDhYObQdCAHZJEk5nD0YCeksUDn1JQ094SENEeUsRQHZIGAZ4QxIEdkJCQmoLQgJmDBIHZwkTR3xMQkd4Q0EOfk0YBHxDS0Z6T0YGagdBBH9CFkV/SUVGf00YBXZLRE5sDRgPfk9GQm4LSgVsDksAfUpAQW4ORE59Q0IAZg0SDndLFAJ6S0ZOfUkRT2gMQwRpDxEAZgxKRnhDQER2QkJCek8QQnZIQEdnCUEHbAgQB3hDE05+TRhEfEMZBnpPRkZqBxMEf0IWRX9JF0ZvCUoFdksWTnxJGE9+T0ZCfk8YRXxKGQB9SkBBfkpETm0HQgBmDRIOZw9GQnpLRg5tDREPaAwRBHlLQ0BmDEoGaAdARHZCQgJqCxBCdkhAR2cJQUd8TBAHeENBTn5NGERsB0sGagsURnpDQUR/QhYFf0lFRm8JGAV2SxYObA0YT24LRgJuC0oFfEpLQH1KQAFuDhYOfUMQAHZJQE53SxRCag9GDn1JEU94SEMP"));
                        if (tt.Contains(ff) || tt.Contains(ff2) || tt.Contains(pbin))
                        {
                            re.rep("hosts file patch (p-a.us)" + zbYG43UH.____());
                            Allowrun = false;
                            writer.append(1, "bA1KT35PFEJuCxhFfEpLQH1KQEFuDhYOfUMQQHZJEg5nD0YCag8UTm0NQ094SEMEaQ8RAHZIGAZ4QxJEdkIQAmoLEAJmDBJHZwkTR3xMQkdoBxMOfk0YBHxDGQZ6TxRGagdBBG8GFgVvDUVGf01KRWYPFk58SRgPfk9GQm4LSkVsDhkAbQ4SQW4OFk59Q0JAdklADndLFAJ6S0ZOfUkRD2gMQwR5SxEAZgwYRmgHQERmBhBCagsQAnZIQAdnCRMHbAhCB2gHQQ5+TUpEfENLBmoLRkZ6QxMEf0JERW8NRUZvCRgFZg8WTmwNGE9+T0ZCfk8YRWwOGQB9ShIBfkpEDm0HQgB2SRJOd0tGQnpLRg5tDUNPaAwRBHlLQ0BmDEoGaAcSBGYGEEJqCxBCdkhAR2cJQQdsCBAHeEMTDm4JGARsB0sGagtGBmoHE0R/QkRFbw1FRn9NGEV2SxYOfElKT24LFAJuCxhFbA4ZQH1KEgFuDkRObQcQAHZJEg5nDxRCag9GDm0NEQ9oDENEeUtDAGYMGAZoBxIEdkIQQnpPEAJmDBIHZwkTR2wIEEd4Q0FObgkYRHxDGQZ6T0ZGagdBRG8GRAVvDRcGbwlKRWYPRE5sDRhPbgsUAn5PGEV8SktAbQ5AAW4ORA59Q0JAdklADmcPFAJqDxQOfUkRT2gMQ0RpD0MAZgxKRmgHQER2QkJCagtCQmYMEgd3TRNHfEwQR2gHQQ5uCRgEbAdLRnpPRkZ6Q0EEbwYWRX9JF0ZvCRhFZg9EDnxJGE9+T0ZCfk9KRXxKGUB9ShIBfkpETn1DEEBmDUAOZw8UAmoPRk59SUMPaAwRBHlLEUB2SBhGaAcSRGYGQgJqCxBCdkhAR3dNQUd8TEIHeEMTDn5NGAR8Q0tGagtGBnpDEwRvBhZFf0lFRm8JGEV2SxYOfEkYD24LFAJuC0oFbA5LAH1KEkF+SkRObQdCQHZJEg53SxRCeksUTm0NEQ9oDBFEaQ8RQHZISgZoB0BEZgYQAnpPEAJmDBJHZwlBB2wIEAdoB0FOfk1KBGwHGQZqCxQGekMTRH9CFgVvDRcGbwlKBXZLFgU=");
                            Kill.Run();
                        }
                        else
                        {
                            Allowrun = true;
                            return;
                        }
                    }
                    catch
                    {

                        Allowrun = false;
                        MessageBox.Show(Crypt.Decode("bA1KT24LFEJ+T0pFfEpLQG0OEkF+ShYOfUMQAHZJQE5nD0YCag9GDn1JEU94SENEeUtDAHZIGAZ4Q0BEdkIQQmoLEAJmDBJHZwkTR3xMQgdoBxMObgkYBHxDGUZ6TxQGagdBBG8GFkVvDUVGf01KRWYPRE5sDRhPfk8UQm4LGEVsDksAbQ5AQW4OFk59Q0JAdklADndLFAJ6S0ZObQ1DD2gMQwR5SxEAZgwYRnhDQARmBhACek8QQnZIEkdnCRNHbAhCB2gHEw5+TRhEfENLRnpPFEZ6QxMEf0IWBX9JF0ZvCUoFZg8WDmwNSk9uC0ZCfk9KBWwOGUB9ShIBfkpETm0HEABmDUAOd0sUQnpLFA59SUNPaAwRBHlLEQB2SEpGaAdARGYGEAJ6TxBCdkhAR3dNQQd8TBAHeENBTm4JSkRsBxkGagsURmoHE0R/QkQFbw0XBn9NGAV2SxZOfEkYD24LRgJuCxhFfEpLQH1KQAFuDkROfUMQAHZJQE5nD0ZCag9GDm0NQ09oDENEeUtDAGYMSkZoBxIEdkJCAmoLEAJmDBIHZwkTR2wIEEd4Q0EObgkYBGwHGQZ6TxRGekMTBG8GRAVvDRdGbwlKRXZLRA5sDRgPfk8UAn5PGAV8SksAbQ5AAW4ORA59QxBAdklADmcPFAJ6SxROfUkRT2gMEURpD0MAdkhKRmgHQER2QkJCek9CAnZIEgd3TUFHfEwQB2gHEw5uCRgEfENLRnpPRgZqBxMEbwYWBX9JF0Z/TRgFZg8WDmwNGE9uCxRCfk9KRXxKSwBtDhIBfkoWDn1DQgBmDUAOd0sUAmoPFE5tDUNPaAwRRGkPEQB2SBhGaAcSBGYGQgJqC0ICZgwSR3dNQUd8TEJHaAcTDn5NGAR8Q0sGagtGBnpDEwR/QkRFf0lFRm8JSkV2SxYOfEkYT35PFEJuCxgFbA4ZQG0OEkF+SkQObQdCQGYNEg53SxQCektGDm0NEQ9oDBFEaQ8RQHZISgZoBxIEZgYQAnpPQkJ2SBIHZwlBB2wIQgd4QxNObglKRGwHGUZqCxQGekNBRH9CFkVvDUUGbwlKRWYPFk58SUpPfk8UQn5PGAV8SktAbQ5AAW4OFg5tBxBAZg0STndLRkJqD0YObQ0RD3hIEQRpDxEAZgxKBmgHQARmBhBCek9CQmYMQEd3TRNHfEwQB3hDQU5uCUpEfENLBmoLFEZ6Q0FEf0JEBW8NFwZvCRhFZg9EDmwNSg9uC0YCfk9KRXxKS0B9SkABbg4WDn1DQkB2SRJOZw9GAmoPFE5tDUNPeEhDRGkPEQB2SBgGeENARHZCEEJqCxACZgwSR2cJE0d8TEJHaAcTTn5NGAR8QxkGek8UBmoHQQRvBhZFbw1FRm8JSkVmDxZOfEQFBA=="), Crypt.Decode("bA1KT35PFEJuCxhFbA5LQG0OEkFuDhZOfUMQAHZJEg5nD0ZCag8UTm0NQ094SEMEaQ9DQHZIGAZ4Q0BEdkIQQmoLQgJmDEBHZwlBR3xMQgdoBxMOfk0YBHxDGQZ6TxQGagcTBG8GFkVvDRdGf00YRWYPRE58SRgPfk9GQm4LSkVsDksAfUoSQX5KFk59Q0JAdklADndLFAJ6S0ZObQ1DTw=="), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Kill.Run();
                    }
                }

            }
            catch
            {
                Allowrun = false;
                MessageBox.Show(Crypt.Decode("bA1KT24LRkJuCxhFfEpLQH1KQAF+ShYOfUNCQGYNQA5nD0YCeksUDm0NEU9oDENEaQ8RQGYMGAZ4Q0BEZgZCAmoLQgJmDEBHZwlBR3xMQgdoB0FObgkYBHxDGUZ6TxQGagcTBG8GFkVvDRdGf01KRXZLFk58SRgPfk9GQm4LSgVsDhkAbQ4SQW4OFk59Q0JAZg1ATmcPFAJ6SxQOfUlDD2gMQwR5SxEAdkhKRnhDQER2QkICagsQQnZIEkdnCRNHbAhCB2gHQQ5+TUpEfENLBmoLFAZqBxNEf0IWRW8NF0ZvCUoFdktETmwNSk9+T0ZCfk9KBXxKGQB9SkBBfkoWDm0HEABmDRJOZw8UQnpLRk5tDUNPaAwRBHlLEQB2SEoGaAdABGYGQgJ6TxBCZgxAR2cJQQd8TBAHeENBTn5NGERsBxkGagsURmoHE0R/QkRFf0kXRm8JGAV2SxZObA0YD24LRgJ+TxgFfEoZQH1KQEFuDkROfUMQQHZJEk5nDxRCag9GDm0NQ09oDENEeUtDQHZISgZoBxIEdkJCQnpPEEJmDEAHZwkTB2wIQkd4Q0EObgkYBGwHGQZ6TxQGekNBRG8GRAVvDRcGbwlKRXZLRA5sDUpPbgsUQn5PGAV8SktAbQ4SQW4ORE59QxBAdkkSTndLFEJ6SxQOfUkRT3hIQ0RpDxEAZgwYRmgHEkR2QkJCagsQAmYMEgd3TRMHfExCB2gHQQ5+TRgEbAcZRnpPRkZ6QxNEbwYWRX9JF0ZvCRhFZg9EDmwNGE9uC0ZCfk9KBWwOGQBtDhIBfkoWTn1DEABmDRIOZw8UQmoPFE59SUNPeEhDBHlLEQB2SBgGaAdABGYGEAJqCxBCZgwSR3dNQQdsCEJHaAcTDn5NGARsBxlGagtGBmoHEwRvBkRFf0lFRn9NSgVmDxZOfEkYT24LFEJuC0oFbA5LQG0OQEF+SkQObQdCQGYNEk53SxRCektGDm0NQw94SBFEeUtDQGYMSkZoBxJEZgYQAmoLEAJmDBIHZwlBR3xMEEdoBxNOfk1KBGwHSwZqCxRGekNBRH9CREVvDRcGbwkYRWYPFk58SUpPfk9GQn5PGAV8ShlAbQ4SAW4ORA59QxBAZg0STndLRgJqDxRObQ0RD3hIEQRpDxEAZgxKBmgHQAR2QhBCek9CQmYMQAd3TRNHfEwQR2gHE05uCUoEfEMZRmoLFEZ6Q0EEbwYWBW8NFwZ/TRgFdktEDmwNSg9uCxRCfk8YRXxKS0B9SkBBbg4WDn1DEEB2SRIOZw9GAmoPRg5tDUNPaAxDRHlLQ0BmDBhGeEMSRGYGEEJqC0ICdkgSB2cJE0d8TEIHaAcTDm4JGAR8Q0sGagsUBmoHEwRvBhZFbw0XRn9NSkVmD0RObA0YD35PFAJuCxgFbA5LAG0OEgF+ShZOfUNCQGYNQA5nDxQCeksUTn1JEQ9oDEMEeUsRQHZIGEZ4Q0BEZgZCQnpPEAJ2SBIHd01BR2wIQgd4QxMObgkYRGwHS0ZqCxRGagcTBH9CREV/SUVGbwlKBXZLFk5sDRhPfk9GQn5PSgVsDhlAfUoSAX5KRE4="), Crypt.Decode("bA1KT35PFEJuCxhFbA5LQG0OEkFuDhZOfUMQAHZJEg5nD0ZCag8UTm0NQ094SEMEaQ9DQHZIGAZ4Q0BEdkIQQmoLQgJmDEBHZwlBR3xMQgdoBxMOfk0YBHxDGQZ6TxQGagcTBG8GFkVvDRdGf00YRWYPRE58SRgPfk9GQm4LSkVsDksAfUoSQX5KFk59Q0JAdklADndLFAJ6S0ZObQ1DTw=="), MessageBoxButtons.OK, MessageBoxIcon.Error);
                Kill.Run();
            }

        }
    }
    public class Class7
    {
        public static bool Allowrun = false;
        public static async void isRealSite()
        {
            await Task.Delay(0);
            Allowrun = false;
            try
            {
                string ff = Crypt.Decode("bA0YD35PFEJuC0pFbA5LAG0OEkFuDhZOfUNCQHZJEk5nDxQCag9GDn1JEU9oDEMEaQ8RAGYMGEZ4Q0BEZgYQQmoLEAJmDEAHd00TR2wIQgdoBxMObgkYRHxDS0ZqCxRGagcTBH9CREVvDRdGbwlKRXZLRA5sDRhPfk9GQm4LSkVsDhkAfUoSQW4ORAU=");
                string ff2 = Crypt.Decode("bA0YD35PFEJuC0pFbA5LAG0OEkFuDhZOfUNCQHZJEk5nDxQCag9GDn1JEU9oDEMEaQ8RAGYMGEZ4Q0BEZgYQQmoLEAJmDEAHd00TR2wIQgdoBxMObgkYRHxDS0ZqCxRGagcTBH9CREVvDUVGbwlKRXZLRA5sDRhPfk9GQm4LSkVsDhkAfUoSQW4ORAU=");
                string pbin = Crypt.Decode("bA1KD35PFEJuCxhFfEpLQG0OEkF+ShYOfUNCQGYNQA5nD0YCeksUDm0NEU94SENEaQ9DQHZIGAZ4QxJEZgZCQmoLQgJmDEBHZwlBR3xMQkd4Q0EObgkYRHxDGQZ6T0ZGagdBBG8GFkV/SUVGf01KRXZLRA58SRgPfk8UAn5PGAU=");

                IPAddress[] aIPHostAddresses = Dns.GetHostAddresses(pbin);
                bool b1 = false;
                string addr = "";
                foreach (IPAddress ipHost in aIPHostAddresses)
                    if (ipHost.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        addr = ipHost.ToString();
                        b1 = true;
                    }


                if (!b1)
                {
                    foreach (IPAddress ipHost in aIPHostAddresses)
                        if (ipHost.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            IPHostEntry ihe = Dns.GetHostEntry(ipHost);
                            foreach (IPAddress ipEntry in ihe.AddressList)
                                if (ipEntry.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                    addr = ipEntry.ToString();
                        }
                }
                if (addr != ff && addr != ff2)
                {
                        re.rep("wrong site ip (pbin)" + zbYG43UH.____());
                        writer.append(1, "bA1KT24LFEJuC0pFfEpLQG0OEgFuDhYOfUMQAHZJQA5nD0YCeksUTn1JEU94SEMEaQ9DQGYMGAZ4QxIEZgYQAmoLQgJmDEAHd00TR3xMQkdoB0EOfk0YRHxDGUZqCxRGagcTBG8GRAVvDUVGbwlKRWYPFk5sDRgPbgsUAm4LGEVsDksAbQ5AAX5KRE59Q0IAZg0SDndLFAJ6S0ZOfUkRT2gMEQRpDxFAZgwYRnhDQARmBhACek8QAnZIEgdnCRMHbAhCB3hDEw5uCRhEfENLRmoLRkZ6QxNEf0IWRW8NF0ZvCUoFZg9ETmwNSk9+T0YCbgsYRWwOGUB9ShJBbg4WTm0HQgBmDRJOd0tGQnpLRk59SUMPeEgRBHlLQ0BmDEpGaAdABHZCEEJ6TxBCdkhAB2cJQUd8TBAHeENBTm4JGERsB0sGek8UBmoHE0R/QkRFbw1FRn9NGAV2SxZOfEkYT24LFAJuC0oFfEoZCw==");
                        Allowrun = false;
                        Kill.Run();
                }
                else
                {
                    try
                    {
                        string tt = File.ReadAllText(Crypt.Decode("bA1KT24LFEJ+T0pFbA5LAH1KEgFuDhYObQdCAHZJEk5nD0YCeksUDn1JQ094SENEeUsRQHZIGAZ4QxIEdkJCQmoLQgJmDBIHZwkTR3xMQkd4Q0EOfk0YBHxDS0Z6T0YGagdBBH9CFkV/SUVGf00YBXZLRE5sDRgPfk9GQm4LSgVsDksAfUpAQW4ORE59Q0IAZg0SDndLFAJ6S0ZOfUkRT2gMQwRpDxEAZgxKRnhDQER2QkJCek8QQnZIQEdnCUEHbAgQB3hDE05+TRhEfEMZBnpPRkZqBxMEf0IWRX9JF0ZvCUoFdksWTnxJGE9+T0ZCfk8YRXxKGQB9SkBBfkpETm0HQgBmDRIOZw9GQnpLRg5tDREPaAwRBHlLQ0BmDEoGaAdARHZCQgJqCxBCdkhAR2cJQUd8TBAHeENBTn5NGERsB0sGagsURnpDQUR/QhYFf0lFRm8JGAV2SxYObA0YT24LRgJuC0oFfEpLQH1KQAFuDhYOfUMQAHZJQE53SxRCag9GDn1JEU94SEMP"));
                        if (tt.Contains(ff) || tt.Contains(ff2) || tt.Contains(pbin))
                        {
                            re.rep("hosts file patch (pbin)" + zbYG43UH.____());
                            Allowrun = false;
                            writer.append(1, "bA1KT35PFEJuCxhFfEpLQH1KQEFuDhYOfUMQQHZJEg5nD0YCag8UTm0NQ094SEMEaQ8RAHZIGAZ4QxJEdkIQAmoLEAJmDBJHZwkTR3xMQkdoBxMOfk0YBHxDGQZ6TxRGagdBBG8GFgVvDUVGf01KRWYPFk58SRgPfk9GQm4LSkVsDhkAbQ4SQW4OFk59Q0JAdklADndLFAJ6S0ZOfUkRD2gMQwR5SxEAZgwYRmgHQERmBhBCagsQAnZIQAdnCRMHbAhCB2gHQQ5+TUpEfENLBmoLRkZ6QxMEf0JERW8NRUZvCRgFZg8WTmwNGE9+T0ZCfk8YRWwOGQB9ShIBfkpEDm0HQgB2SRJOd0tGQnpLRg5tDUNPaAwRBHlLQ0BmDEoGaAcSBGYGEEJqCxBCdkhAR2cJQQdsCBAHeEMTDm4JGARsB0sGagtGBmoHE0R/QkRFbw1FRn9NGEV2SxYOfElKT24LFAJuCxhFbA4ZQH1KEgFuDkRObQcQAHZJEg5nDxRCag9GDm0NEQ9oDENEeUtDAGYMGAZoBxIEdkIQQnpPEAJmDBIHZwkTR2wIEEd4Q0FObgkYRHxDGQZ6T0ZGagdBRG8GRAVvDRcGbwlKRWYPRE5sDRhPbgsUAn5PGEV8SktAbQ5AAW4ORA59Q0JAdklADmcPFAJqDxQOfUkRT2gMQ0RpD0MAZgxKRmgHQER2QkJCagtCQmYMEgd3TRNHfEwQR2gHQQ5uCRgEbAdLRnpPRkZ6Q0EEbwYWRX9JF0ZvCRhFZg9EDnxJGE9+T0ZCfk9KRXxKGUB9ShIBfkpETn1DEEBmDUAOZw8UAmoPRk59SUMPaAwRBHlLEUB2SBhGaAcSRGYGQgJqCxBCdkhAR3dNQUd8TEIHeEMTDn5NGAR8Q0tGagtGBnpDEwRvBhZFf0lFRm8JGEV2SxYOfEkYD24LFAJuC0oFbA5LAH1KEkF+SkRObQdCQHZJEg53SxRCeksUTm0NEQ9oDBFEaQ8RQHZISgZoB0BEZgYQAnpPEAJmDBJHZwlBB2wIEAdoB0FOfk1KBGwHGQZqCxQGekMTRH9CFgVvDRcGbwlKBXZLFgU=");
                            Kill.Run();
                        }
                        else
                        {
                            Allowrun = true;
                            return;
                        }
                    }
                    catch
                    {
                       
                        Allowrun = false;
                        MessageBox.Show(Crypt.Decode("bA1KT24LFEJ+T0pFfEpLQG0OEkF+ShYOfUMQAHZJQE5nD0YCag9GDn1JEU94SENEeUtDAHZIGAZ4Q0BEdkIQQmoLEAJmDBJHZwkTR3xMQgdoBxMObgkYBHxDGUZ6TxQGagdBBG8GFkVvDUVGf01KRWYPRE5sDRhPfk8UQm4LGEVsDksAbQ5AQW4OFk59Q0JAdklADndLFAJ6S0ZObQ1DD2gMQwR5SxEAZgwYRnhDQARmBhACek8QQnZIEkdnCRNHbAhCB2gHEw5+TRhEfENLRnpPFEZ6QxMEf0IWBX9JF0ZvCUoFZg8WDmwNSk9uC0ZCfk9KBWwOGUB9ShIBfkpETm0HEABmDUAOd0sUQnpLFA59SUNPaAwRBHlLEQB2SEpGaAdARGYGEAJ6TxBCdkhAR3dNQQd8TBAHeENBTm4JSkRsBxkGagsURmoHE0R/QkQFbw0XBn9NGAV2SxZOfEkYD24LRgJuCxhFfEpLQH1KQAFuDkROfUMQAHZJQE5nD0ZCag9GDm0NQ09oDENEeUtDAGYMSkZoBxIEdkJCAmoLEAJmDBIHZwkTR2wIEEd4Q0EObgkYBGwHGQZ6TxRGekMTBG8GRAVvDRdGbwlKRXZLRA5sDRgPfk8UAn5PGAV8SksAbQ5AAW4ORA59QxBAdklADmcPFAJ6SxROfUkRT2gMEURpD0MAdkhKRmgHQER2QkJCek9CAnZIEgd3TUFHfEwQB2gHEw5uCRgEfENLRnpPRgZqBxMEbwYWBX9JF0Z/TRgFZg8WDmwNGE9uCxRCfk9KRXxKSwBtDhIBfkoWDn1DQgBmDUAOd0sUAmoPFE5tDUNPaAwRRGkPEQB2SBhGaAcSBGYGQgJqC0ICZgwSR3dNQUd8TEJHaAcTDn5NGAR8Q0sGagtGBnpDEwR/QkRFf0lFRm8JSkV2SxYOfEkYT35PFEJuCxgFbA4ZQG0OEkF+SkQObQdCQGYNEg53SxQCektGDm0NEQ9oDBFEaQ8RQHZISgZoBxIEZgYQAnpPQkJ2SBIHZwlBB2wIQgd4QxNObglKRGwHGUZqCxQGekNBRH9CFkVvDUUGbwlKRWYPFk58SUpPfk8UQn5PGAV8SktAbQ5AAW4OFg5tBxBAZg0STndLRkJqD0YObQ0RD3hIEQRpDxEAZgxKBmgHQARmBhBCek9CQmYMQEd3TRNHfEwQB3hDQU5uCUpEfENLBmoLFEZ6Q0FEf0JEBW8NFwZvCRhFZg9EDmwNSg9uC0YCfk9KRXxKS0B9SkABbg4WDn1DQkB2SRJOZw9GAmoPFE5tDUNPeEhDRGkPEQB2SBgGeENARHZCEEJqCxACZgwSR2cJE0d8TEJHaAcTTn5NGAR8QxkGek8UBmoHQQRvBhZFbw1FRm8JSkVmDxZOfEQFBA=="), Crypt.Decode("bA1KT35PFEJuCxhFbA5LQG0OEkFuDhZOfUMQAHZJEg5nD0ZCag8UTm0NQ094SEMEaQ9DQHZIGAZ4Q0BEdkIQQmoLQgJmDEBHZwlBR3xMQgdoBxMOfk0YBHxDGQZ6TxQGagcTBG8GFkVvDRdGf00YRWYPRE58SRgPfk9GQm4LSkVsDksAfUoSQX5KFk59Q0JAdklADndLFAJ6S0ZObQ1DTw=="), MessageBoxButtons.OK, MessageBoxIcon.Error);
                        Kill.Run();
                    }
                }

            }
            catch
            {
                Allowrun = false;
                MessageBox.Show(Crypt.Decode("bA1KT35PRkJuC0pFfEpLQH1KQAF+ShYOfUNCQHZJEg5nDxQCag8UTm0NEU94SENEeUtDAGYMGAZ4QxJEdkIQAmoLQgJmDBIHZwlBR3xMQkdoB0FObgkYRHxDGUZqCxRGagdBBH9CFgVvDRdGf01KRXZLRA58SRhPfk8UQm4LGEVsDksAbQ4SQX5KFk59Q0JAZg1ATndLFEJ6SxRObQ0RT2gMQwRpDxFAdkhKRnhDQER2QkICek8QAnZIEgd3TUFHbAhCB2gHQQ5+TRhEfENLRmoLRkZ6QxMEf0IWRW8NRQZvCUoFdksWDmwNGE9+T0ZCbgtKRXxKGQB9ShJBfkoWTm0HEABmDRJOZw8UQnpLRg5tDUNPaAwRBHlLEQB2SEoGaAcSBGYGEEJqCxBCdkhAB2cJQUdsCBAHeEMTDm4JGERsB0sGagsUBmoHQURvBkRFbw0XRm8JGAV2SxYObA0YD24LRgJuC0oFfEoZQH1KQAFuDkRObQcQAHZJEk53SxQCag9GDn1JEU94SBFEeUtDQHZISgZoBxIEdkIQQnpPEAJmDEAHd00TB2wIEEdoB0FObgkYRGwHGQZ6TxRGekNBRG8GRAVvDUUGf01KRXZLRA5sDRgPbgsUQn5PGEVsDhlAbQ5AAX5KFg5tBxBAdklATndLFEJqDxQOfUkRT3hIEQRpDxEAZgwYRmgHEkR2QkICagtCQmYMEgd3TUFHbAhCR2gHQQ5uCRhEbAdLRnpPRkZ6QxNEf0IWBX9JFwZ/TUpFZg9EDmwNGA9uC0ZCfk9KBWwOGQBtDhJBfkoWTm0HEEBmDUAOd0sUAmoPFE59SUNPeEhDBHlLEUB2SBhGaAcSRGYGQgJ6TxACdkhAR3dNQUd8TEIHeEMTDn5NSkRsB0tGagtGBmoHQUR/QkRFbw1FRn9NSgVmDxYObA1KD35PFEJuC0oFbA5LAH1KEkF+ShZOfUMQQHZJEg53SxRCektGTm0NEQ9oDBFEaQ8RQHZISgZ4QxJEdkIQAnpPEAJ2SEAHZwlBB3xMEAdoB0FObglKRGwHGUZqCxQGekMTRG8GFgVvDUUGf00YRXZLFk58SUpPbgtGQn5PGEV8ShkAfUoSQW4OFg5tBxBAZg0STndLFEJ6SxRObQ0RD2gMQ0R5S0MAZgxKRmgHQERmBkJCek8QQmYMQEdnCRNHfEwQR2gHE05uCUoEbAdLRmoLFEZ6Q0FEf0JEBX9JFwZ/TUpFZg9EDmwNSg9+TxQCbgsYRWwOS0BtDhJBbg4WDn1DQkBmDUAOZw9GAmoPRk5tDUNPeEhDBGkPQ0BmDBgGeEMSRHZCEAJqCxACZgwSR2cJE0d8TEJHeEMTTn5NGAR8Q0tGagtGBmoHEwRvBhZFbw0XRn9NSkVmD0RObA0YD35PFAJ+T0oFbA5LAH1KEgF+SkROfUNCQHZJQA5nDxRCeksUTm0NEU9oDEMEaQ8RQHZISkZ4Q0AEZgZCQnpPEAJ2SEBHZwlBR2wIQgd4QxNOfk0YRHxDS0ZqC0ZGekMTBH9CFgV/SUVGbwlKBXZLFg5sDRhPfk9GQn5PSkVsDhkAfUpAAW4OFg5tBxAAZg1ADndLFAk="), Crypt.Decode("bA1KT35PFEJuCxhFbA5LQG0OEkFuDhZOfUMQAHZJEg5nD0ZCag8UTm0NQ094SEMEaQ9DQHZIGAZ4Q0BEdkIQQmoLQgJmDEBHZwlBR3xMQgdoBxMOfk0YBHxDGQZ6TxQGagcTBG8GFkVvDRdGf00YRWYPRE58SRgPfk9GQm4LSkVsDksAfUoSQX5KFk59Q0JAdklADndLFAJ6S0ZObQ1DTw=="), MessageBoxButtons.OK, MessageBoxIcon.Error);
                Kill.Run();
            }
          
        }
    }
    public class Class13
    {
        public static byte[] g(string k)
        {
            return Convert.FromBase64String(k);
        }
    }
}
