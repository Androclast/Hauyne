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
using System.Runtime.Versioning;
using System.Text;

[SupportedOSPlatform("linux")]
static partial class LinuxInjector
{
    static readonly bool Debug = Environment.GetEnvironmentVariable("HAUYNE_DEBUG") == "1";

    const int PTRACE_PEEKDATA = 2;
    const int PTRACE_POKEDATA = 5;
    const int PTRACE_CONT = 7;
    const int PTRACE_GETREGS = 12;
    const int PTRACE_SETREGS = 13;
    const int PTRACE_ATTACH = 16;
    const int PTRACE_DETACH = 17;

    const int RTLD_NOW = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    struct UserRegsStruct
    {
        public ulong r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
        public ulong rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags;
        public ulong rsp, ss, fs_base, gs_base, ds, es, fs, gs;
    }

    [LibraryImport("libc", SetLastError = true)]
    private static partial long ptrace(int request, int pid, nint addr, nint data);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int waitpid(int pid, out int status, int options);

    public static void Inject(Process process, string soPath)
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("Linux injection requires x86-64");

        int pid = process.Id;

        if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0)
            throw new InvalidOperationException($"ptrace ATTACH failed: {Marshal.GetLastPInvokeError()}");

        waitpid(pid, out _, 0);

        try
        {
            var oldRegs = GetRegs(pid);
            var regs = oldRegs;

            nint dlopenAddr = FindDlopenInTarget(pid);

            byte[] pathBytes = Encoding.UTF8.GetBytes(soPath + '\0');
            nint pathAddr = (nint)((long)(oldRegs.rsp - 256) & ~7L);
            WriteMemory(pid, pathAddr, pathBytes);

            long savedInsn = ptrace(PTRACE_PEEKDATA, pid, (nint)oldRegs.rip, 0);
            ptrace(PTRACE_POKEDATA, pid, (nint)oldRegs.rip, (nint)((savedInsn & ~0xFFL) | 0xCC));

            regs.rip = (ulong)dlopenAddr;
            regs.rdi = (ulong)pathAddr;
            regs.rsi = RTLD_NOW;
            regs.rsp = (((ulong)pathAddr - 16) & ~0xFUL) - 8;
            regs.orig_rax = unchecked((ulong)-1L);

            ptrace(PTRACE_POKEDATA, pid, (nint)regs.rsp, (nint)oldRegs.rip);

            SetRegs(pid, regs);

            if (Debug)
            {
                Console.WriteLine($"[hauyne] dlopen=0x{dlopenAddr:x} pathAddr=0x{pathAddr:x} origRip=0x{oldRegs.rip:x} newRsp=0x{regs.rsp:x}");
                Console.WriteLine($"[hauyne] path: {soPath}");
            }

            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, out int status, 0);

            if (Debug)
            {
                int stopSig = (status & 0x7f) == 0x7f ? (status >> 8) & 0xff : -1;
                var afterRegs = GetRegs(pid);
                Console.WriteLine($"[hauyne] waitpid status=0x{status:x} stopSig={stopSig} (5=SIGTRAP expected)");
                Console.WriteLine($"[hauyne] after: rip=0x{afterRegs.rip:x} rax=0x{afterRegs.rax:x} (dlopen return)");
                if (afterRegs.rax == 0)
                    Console.WriteLine("[hauyne] !!! dlopen returned NULL in target !!!");
            }

            ptrace(PTRACE_POKEDATA, pid, (nint)oldRegs.rip, (nint)savedInsn);
            SetRegs(pid, oldRegs);
        }
        finally
        {
            ptrace(PTRACE_DETACH, pid, 0, 0);
        }
    }

    static UserRegsStruct GetRegs(int pid)
    {
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<UserRegsStruct>());
        try
        {
            if (ptrace(PTRACE_GETREGS, pid, 0, ptr) < 0)
                throw new InvalidOperationException($"PTRACE_GETREGS failed: {Marshal.GetLastPInvokeError()}");
            return Marshal.PtrToStructure<UserRegsStruct>(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    static void SetRegs(int pid, UserRegsStruct regs)
    {
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<UserRegsStruct>());
        try
        {
            Marshal.StructureToPtr(regs, ptr, false);
            if (ptrace(PTRACE_SETREGS, pid, 0, ptr) < 0)
                throw new InvalidOperationException($"PTRACE_SETREGS failed: {Marshal.GetLastPInvokeError()}");
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    static void WriteMemory(int pid, nint addr, byte[] data)
    {
        for (int i = 0; i < data.Length; i += sizeof(long))
        {
            long word = 0;
            int remaining = Math.Min(sizeof(long), data.Length - i);

            if (remaining < sizeof(long))
            {
                word = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);
                long mask = (1L << (remaining * 8)) - 1;
                word &= ~mask;
            }

            for (int j = 0; j < remaining; j++)
                word |= (long)data[i + j] << (j * 8);

            ptrace(PTRACE_POKEDATA, pid, addr + i, (nint)word);
        }
    }

    static nint FindDlopenInTarget(int pid)
    {
        nint libHandle;
        if (!NativeLibrary.TryLoad("libdl.so.2", out libHandle))
            libHandle = NativeLibrary.Load("libc");

        nint ourDlopen = NativeLibrary.GetExport(libHandle, "dlopen");

        (nint ourBase, string? libPath) = FindLoadBase("/proc/self/maps", ourDlopen);
        if (ourBase == 0 || libPath == null)
            throw new InvalidOperationException("Could not locate dlopen mapping");

        string libName = Path.GetFileName(libPath);
        (nint targetBase, _) = FindLoadBaseByName($"/proc/{pid}/maps", libName);
        if (targetBase == 0)
            throw new InvalidOperationException($"Could not find {libName} in target");

        return (nint)((long)targetBase + ((long)ourDlopen - (long)ourBase));
    }

    static (nint baseAddr, string? path) FindLoadBase(string mapsPath, nint containedAddr)
    {
        string? matchedPath = null;
        nint segmentBase = 0;

        foreach (var line in File.ReadLines(mapsPath))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 6) continue;

            var range = parts[0].Split('-');
            nint start = (nint)Convert.ToInt64(range[0], 16);
            nint end = (nint)Convert.ToInt64(range[1], 16);

            if ((ulong)containedAddr >= (ulong)start && (ulong)containedAddr < (ulong)end)
            {
                matchedPath = parts[5];
                segmentBase = start;
                break;
            }
        }

        if (matchedPath == null)
            return (0, null);

        foreach (var line in File.ReadLines(mapsPath))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 6 || parts[5] != matchedPath) continue;

            if (parts[2] == "00000000")
            {
                var range = parts[0].Split('-');
                return ((nint)Convert.ToInt64(range[0], 16), matchedPath);
            }
        }

        return (segmentBase, matchedPath);
    }

    static (nint baseAddr, string? path) FindLoadBaseByName(string mapsPath, string libFileName)
    {
        foreach (var line in File.ReadLines(mapsPath))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 6) continue;

            if (Path.GetFileName(parts[5]) != libFileName) continue;

            if (parts[2] == "00000000")
            {
                var range = parts[0].Split('-');
                return ((nint)Convert.ToInt64(range[0], 16), parts[5]);
            }
        }

        return (0, null);
    }
}
