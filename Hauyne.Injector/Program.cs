/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
 * Mozilla Public License, v. 2.0.
 * 
 */

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

var targetProcess = args.Length > 0
    ? Process.GetProcessesByName(args[0]).FirstOrDefault()
    : throw new ArgumentException("Your other argument is the process name without the .exe part mkay");

if (targetProcess == null)
{
    Console.WriteLine("Process not found");
    return 1;
}

var bootstrapName = OperatingSystem.IsWindows() ? "Hauyne.Bootstrap.dll" : "libHauyne.Bootstrap.so";
var bootstrapPath = Path.GetFullPath(bootstrapName, AppContext.BaseDirectory);
if (!File.Exists(bootstrapPath))
{
    Console.WriteLine($"Bootstrap not found: {bootstrapPath}");
    return 1;
}

if (!IsDotNetProcess(targetProcess))
{
    Console.WriteLine($"{targetProcess.ProcessName} ({targetProcess.Id}) does not look like a .NET process (hostfxr not loaded)");
    return 1;
}

if (OperatingSystem.IsWindows())
    Injector.Inject(targetProcess, bootstrapPath);
else if (OperatingSystem.IsLinux())
    LinuxInjector.Inject(targetProcess, bootstrapPath);
else
    throw new PlatformNotSupportedException();

Console.WriteLine($"Injected into {targetProcess.ProcessName} ({targetProcess.Id})");
return 0;

static bool IsDotNetProcess(Process process)
{
    if (OperatingSystem.IsWindows())
    {
        foreach (ProcessModule module in process.Modules)
            if (string.Equals(module.ModuleName, "hostfxr.dll", StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
    if (OperatingSystem.IsLinux())
    {
        foreach (var line in File.ReadLines($"/proc/{process.Id}/maps"))
            if (line.Contains("/libhostfxr.so"))
                return true;
        return false;
    }
    return false;
}

static partial class Injector
{
    public static void Inject(Process process, string dllPath)
    {
        var pathBytes = Encoding.Unicode.GetBytes(dllPath + '\0');

        var hProcess = OpenProcess(
            ProcessAccess.CreateThread | ProcessAccess.VmOperation |
            ProcessAccess.VmWrite | ProcessAccess.VmRead | ProcessAccess.QueryInformation,
            false, process.Id);

        if (hProcess == nint.Zero)
            throw new InvalidOperationException($"OpenProcess failed: {Marshal.GetLastWin32Error()}");

        try
        {
            var allocated = VirtualAllocEx(hProcess, nint.Zero, (uint)pathBytes.Length,
                AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);

            if (allocated == nint.Zero)
                throw new InvalidOperationException($"VirtualAllocEx failed: {Marshal.GetLastWin32Error()}");

            try
            {
                if (!WriteProcessMemory(hProcess, allocated, pathBytes, (uint)pathBytes.Length, out _))
                    throw new InvalidOperationException($"WriteProcessMemory failed: {Marshal.GetLastWin32Error()}");

                var kernel32 = GetModuleHandle("kernel32.dll");
                if (kernel32 == nint.Zero)
                    throw new InvalidOperationException($"GetModuleHandle(kernel32) failed: {Marshal.GetLastWin32Error()}");

                var loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
                if (loadLibrary == nint.Zero)
                    throw new InvalidOperationException($"GetProcAddress(LoadLibraryW) failed: {Marshal.GetLastWin32Error()}");

                var thread = CreateRemoteThread(hProcess, nint.Zero, 0, loadLibrary, allocated, 0, out _);
                if (thread == nint.Zero)
                    throw new InvalidOperationException($"CreateRemoteThread failed: {Marshal.GetLastWin32Error()}");

                try
                {
                    WaitForSingleObject(thread, 5000);
                }
                finally
                {
                    CloseHandle(thread);
                }
            }
            finally
            {
                VirtualFreeEx(hProcess, allocated, 0, FreeType.Release);
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    #region This is all copypasted might as well not look here
    [Flags]
    enum ProcessAccess : uint
    {
        CreateThread = 0x0002,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        QueryInformation = 0x0400
    }

    [Flags]
    enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000
    }

    enum MemoryProtection : uint
    {
        ReadWrite = 0x04
    }

    enum FreeType : uint
    {
        Release = 0x8000
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(ProcessAccess access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint VirtualAllocEx(nint hProcess, nint address, uint size, AllocationType type, MemoryProtection protect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WriteProcessMemory(nint hProcess, nint address, byte[] buffer, uint size, out nuint written);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualFreeEx(nint hProcess, nint address, uint size, FreeType type);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateRemoteThread(nint hProcess, nint attributes, uint stackSize, nint startAddress, nint parameter, uint flags, out uint threadId);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandle(string moduleName);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetProcAddress(nint hModule, string procName);

    [LibraryImport("kernel32.dll")]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
    #endregion
}