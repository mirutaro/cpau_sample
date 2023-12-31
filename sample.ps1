Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public class Win32API
    {
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(UInt32 sessionId, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
    }
"@

    $sessionId = 2    # You can get sessionId using query session command.
    $TokenHandle = [IntPtr]::Zero
    $success = [Win32API]::WTSQueryUserToken($sessionId, [ref] $TokenHandle)
    if (!$success)
    {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $errorMessage = [System.ComponentModel.Win32Exception]::new($errorCode).Message
    
        "WTSQueryUserToken failed."
        $errorMessage 
        return
    }

    "Token: $TokenHandle"

    $si = New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName = "C:\Windows\System32\notepad.exe"
    $si.Arguments = "C:\temp\test.txt"
    $si.WorkingDirectory = "C:\Windows"

    $sa = New-Object SECURITY_ATTRIBUTES
    $sa.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)

    
    $processInfo = New-Object PROCESS_INFORMATION
    
    $saProcess = New-Object SECURITY_ATTRIBUTES
    $saProcess.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($saProcess)

    $saThread = New-Object SECURITY_ATTRIBUTES
    $saThread.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($saThread)

    $siStartup = New-Object STARTUPINFO
    $siStartup.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($siStartup)

    $env = [IntPtr]::Zero
    [Win32API]::CreateEnvironmentBlock([ref ]$env, [IntPtr]::Zero, $False)

    $createProcessResult = [Win32API]::CreateProcessAsUser(
        $TokenHandle,
        $si.FileName,
        $si.Arguments,
        [ref] $saProcess,
        [ref] $saThread,
        $false,
        1024,
        $env,
        $si.WorkingDirectory,
        [ref] $siStartup,
        [ref] $processInfo)

    if (!$createProcessResult)
    {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $errorMessage = [System.ComponentModel.Win32Exception]::new($errorCode).Message
    
        "CreateProcessAsUser failed."
        $errorMessage 
        return
    }

    "Process ID: $($processInfo.dwProcessId)"
    
    [Win32API]::DestroyEnvironmentBlock($env)

