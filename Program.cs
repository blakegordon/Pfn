// Pfn — RAMMap-style physical page use counts from the command line.
//
// Walks physical ranges (SuperfetchMemoryRangesQuery) then classifies each
// page with SuperfetchPfnQuery. UseDescription 10 is Driver Locked — that is
// where VirtualBox guest RAM shows up on a native VT-x host.
//
// Needs SeProfileSingleProcessPrivilege (an Admin token has it). If started
// unelevated, relaunches with ProcessStartInfo Verb=runas (UAC), then attaches
// back to this console so output stays in the original terminal.
//
//   dotnet run -c Release --
//   Pfn --csv=pfn.csv

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;

namespace PfnUseDump;

internal static partial class Native
{
    internal const int SystemSuperfetchInformation = 79;
    internal const int SuperfetchPfnQuery = 6;
    internal const int SuperfetchMemoryRangesQuery = 17;

    internal const uint SuperfetchVersion = 45;
    internal const uint SuperfetchMagic = 0x6B756843; // 'kuhC'

    internal const int StatusSuccess = 0;
    internal const int StatusBufferTooSmall = unchecked((int)0xC0000023);
    internal const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    internal const int StatusAccessDenied = unchecked((int)0xC0000022);
    internal const int StatusPrivilegeNotHeld = unchecked((int)0xC0000061);

    internal const uint SeProfileSingleProcessPrivilege = 13;

    [LibraryImport("ntdll.dll")]
    internal static partial int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        uint systemInformationLength,
        out uint returnLength);

    [LibraryImport("ntdll.dll")]
    internal static partial int RtlAdjustPrivilege(
        uint privilege,
        [MarshalAs(UnmanagedType.U1)] bool enable,
        [MarshalAs(UnmanagedType.U1)] bool currentThread,
        [MarshalAs(UnmanagedType.U1)] out bool previous);

    internal const uint GenericRead = 0x80000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint FileShareRead = 0x00000001;
    internal const uint FileShareWrite = 0x00000002;
    internal const uint OpenExisting = 3;
    internal const int StdInputHandle = -10;
    internal const int StdOutputHandle = -11;
    internal const int StdErrorHandle = -12;
    internal static readonly IntPtr InvalidHandleValue = new(-1);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AttachConsole(uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool FreeConsole();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool AllocConsole();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
}

internal readonly record struct PhysRange(ulong BasePfn, ulong PageCount);

internal static class Superfetch
{
    // PF_PFN_PRIO_REQUEST (x64):
    //   +0x00 ULONG Version
    //   +0x04 ULONG RequestFlags
    //   +0x08 SIZE_T PfnCount
    //   +0x10 SYSTEM_MEMORY_LIST_INFORMATION (22 * 8 = 176)
    //   +0xC0 MMPFN_IDENTITY PageData[]
    internal const int PfnRequestHeader = 0xC0;
    internal const int MmpfnIdentitySize = 24;
    internal const int BatchPages = 16_384;

    // MMPFN_IDENTITY.u1.e1.UseDescription is the low 4 bits.
    // ListDescription is the next 3 bits.
    internal const int UseDriverLocked = 10;

    internal static readonly string[] UseNames =
    [
        "Process Private",
        "Mapped File",
        "Shareable",           // pagefile-backed mapped
        "Page Table",
        "Paged Pool",
        "Nonpaged Pool",
        "System PTE",
        "Session Private",
        "Metafile",
        "AWE",
        "Driver Locked",
        "Kernel Stack",
    ];

    internal static readonly string[] ListNames =
    [
        "Zeroed",
        "Free",
        "Standby",
        "Modified",
        "ModifiedNoWrite",
        "Bad",
        "Active",
        "Transition",
    ];

    public static void EnablePrivilege()
    {
        int st = Native.RtlAdjustPrivilege(
            Native.SeProfileSingleProcessPrivilege,
            enable: true,
            currentThread: false,
            out _);
        if (st < 0)
        {
            throw new UnauthorizedAccessException(
                "RtlAdjustPrivilege(SeProfileSingleProcessPrivilege) failed " +
                $"(0x{st:X8}). Administrator elevation is required.");
        }
    }

    public static PhysRange[] QueryRanges()
    {
        // Prefer V2 (Windows 10 1903+): Version, Flags, SIZE_T RangeCount, ranges.
        try
        {
            return QueryRangesVersion(2);
        }
        catch (InvalidOperationException)
        {
            return QueryRangesVersion(1);
        }
    }

    private static PhysRange[] QueryRangesVersion(int version)
    {
        uint probe = (uint)(version == 2 ? 24 : 16);
        byte[] buf = new byte[probe];
        WriteUInt32(buf, 0, (uint)version);

        int status = Query(Native.SuperfetchMemoryRangesQuery, buf, out uint needed);
        if (status is Native.StatusBufferTooSmall or Native.StatusInfoLengthMismatch)
        {
            if (needed < 32)
                needed = 4096;
            buf = new byte[needed];
            WriteUInt32(buf, 0, (uint)version);
            status = Query(Native.SuperfetchMemoryRangesQuery, buf, out _);
        }

        if (status < 0)
            throw new InvalidOperationException(
                $"SuperfetchMemoryRangesQuery v{version} failed: 0x{status:X8}");

        uint rangeCount;
        int offset;
        if (version == 2)
        {
            // ULONG Version, ULONG Flags, SIZE_T RangeCount
            rangeCount = (uint)ReadUIntPtr(buf, 8);
            offset = 16;
        }
        else
        {
            rangeCount = ReadUInt32(buf, 4);
            offset = 8;
        }

        var ranges = new PhysRange[rangeCount];
        for (uint i = 0; i < rangeCount; i++)
        {
            ulong basePfn = ReadUIntPtr(buf, offset);
            ulong pages = ReadUIntPtr(buf, offset + 8);
            ranges[i] = new PhysRange(basePfn, pages);
            offset += 16;
        }

        return ranges;
    }

    public static void Classify(
        PhysRange[] ranges,
        ulong[] useCounts,
        ulong[] listCounts,
        Action<ulong, ulong>? progress)
    {
        int capacity = PfnRequestHeader + MmpfnIdentitySize * BatchPages;
        byte[] req = new byte[capacity];

        ulong done = 0;
        ulong total = 0;
        foreach (var r in ranges)
            total += r.PageCount;

        foreach (var range in ranges)
        {
            ulong pfn = range.BasePfn;
            ulong remaining = range.PageCount;
            while (remaining > 0)
            {
                int batch = (int)Math.Min(remaining, BatchPages);
                Array.Clear(req);
                WriteUInt32(req, 0, 1);                         // Version
                WriteUInt32(req, 4, 1);                         // RequestFlags = QUERY_MEMORY_LIST
                WriteUIntPtr(req, 8, (ulong)batch);             // PfnCount

                int ident = PfnRequestHeader;
                for (int i = 0; i < batch; i++)
                {
                    // MMPFN_IDENTITY: u1 (8), PageFrameIndex (8), u2 (8)
                    WriteUIntPtr(req, ident + 8, pfn + (ulong)i);
                    ident += MmpfnIdentitySize;
                }

                int status = Query(Native.SuperfetchPfnQuery, req, out _);
                if (status < 0)
                    throw new InvalidOperationException(
                        $"SuperfetchPfnQuery failed: 0x{status:X8} (PFN 0x{pfn:X})");

                ident = PfnRequestHeader;
                for (int i = 0; i < batch; i++)
                {
                    ulong u1 = ReadUIntPtr(req, ident);
                    int use = (int)(u1 & 0xF);
                    int list = (int)((u1 >> 4) & 0x7);
                    if ((uint)use < (uint)useCounts.Length)
                        useCounts[use]++;
                    if ((uint)list < (uint)listCounts.Length)
                        listCounts[list]++;
                    ident += MmpfnIdentitySize;
                }

                pfn += (ulong)batch;
                remaining -= (ulong)batch;
                done += (ulong)batch;
                progress?.Invoke(done, total);
            }
        }
    }

    private static int Query(int infoClass, byte[] data, out uint returnLength)
    {
        GCHandle pin = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            var header = new SuperfetchHeader
            {
                Version = Native.SuperfetchVersion,
                Magic = Native.SuperfetchMagic,
                InfoClass = infoClass,
                Data = pin.AddrOfPinnedObject(),
                Length = (uint)data.Length,
            };

            GCHandle hdr = GCHandle.Alloc(header, GCHandleType.Pinned);
            try
            {
                return Native.NtQuerySystemInformation(
                    Native.SystemSuperfetchInformation,
                    hdr.AddrOfPinnedObject(),
                    (uint)Marshal.SizeOf<SuperfetchHeader>(),
                    out returnLength);
            }
            finally
            {
                hdr.Free();
            }
        }
        finally
        {
            pin.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SuperfetchHeader
    {
        public uint Version;
        public uint Magic;
        public int InfoClass;
        public IntPtr Data;
        public uint Length;
    }

    private static void WriteUInt32(byte[] b, int o, uint v) =>
        BitConverter.TryWriteBytes(b.AsSpan(o, 4), v);

    private static void WriteUIntPtr(byte[] b, int o, ulong v) =>
        BitConverter.TryWriteBytes(b.AsSpan(o, 8), v);

    private static uint ReadUInt32(byte[] b, int o) => BitConverter.ToUInt32(b, o);

    private static ulong ReadUIntPtr(byte[] b, int o) => BitConverter.ToUInt64(b, o);
}

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            bool help = false;
            string? csv = null;
            bool quiet = false;
            bool top = false;
            uint attachPid = 0;
            foreach (var a in args)
            {
                const string attachPrefix = "--internal-attach-console=";
                if (a.StartsWith(attachPrefix, StringComparison.Ordinal))
                {
                    if (!uint.TryParse(a.AsSpan(attachPrefix.Length), out attachPid))
                        throw new ArgumentException("Invalid --internal-attach-console value");
                    continue;
                }
                if (a is "-h" or "--help" or "/?")
                    help = true;
                else if (a is "-q" or "--quiet")
                    quiet = true;
                else if (a is "-t" or "--top")
                    top = true;
                else if (a.StartsWith("--csv=", StringComparison.OrdinalIgnoreCase))
                    csv = a[6..];
                else if (a == "--csv")
                    throw new ArgumentException("Use --csv=<file>");
                else
                    throw new ArgumentException($"Unknown switch: {a}");
            }

            if (attachPid != 0)
                AttachToConsole(attachPid);

            if (help)
            {
                Console.WriteLine("""
                    Pfn — physical page use counts (RAMMap Use Counts, CLI)

                    Usage:
                      Pfn [--csv=<file>] [--quiet] [--top]

                    Walks every physical page via Superfetch (same source RAMMap
                    uses). Needs elevation; an unelevated launch prompts UAC.
                    On a large machine this takes a while.

                    -t, --top   Omit categories under 1 GiB and sort each
                                section by size, largest first.

                    Driver Locked is the row that holds VirtualBox guest RAM when
                    the VM is using native VT-x (HM), not process private commit.
                    """);
                return 0;
            }

            if (!Environment.Is64BitProcess)
                throw new PlatformNotSupportedException("64-bit only.");

            if (!IsElevated())
            {
                if (!TryRelaunchElevated(args, out int elevatedCode))
                {
                    Console.Error.WriteLine(
                        "Administrator elevation is required. The UAC prompt was declined.");
                    return 1;
                }
                return elevatedCode;
            }

            Superfetch.EnablePrivilege();
            Console.Error.WriteLine("Querying physical ranges...");
            PhysRange[] ranges = Superfetch.QueryRanges();
            ulong pages = 0;
            foreach (var r in ranges)
                pages += r.PageCount;
            Console.Error.WriteLine(
                $"  {ranges.Length} range(s), {pages:N0} pages ({pages * 4096.0 / (1024 * 1024 * 1024):N2} GB).");

            var use = new ulong[16];
            var list = new ulong[8];
            DateTime last = DateTime.MinValue;
            Superfetch.Classify(ranges, use, list, (done, total) =>
            {
                if (quiet)
                    return;
                var now = DateTime.UtcNow;
                if ((now - last).TotalSeconds < 1 && done != total)
                    return;
                last = now;
                double pct = total == 0 ? 100 : 100.0 * done / total;
                Console.Error.Write($"\r  scanned {done:N0}/{total:N0} pages ({pct:N1}%)   ");
            });
            if (!quiet)
                Console.Error.WriteLine();

            PrintUse(use, pages, top);
            Console.WriteLine();
            PrintList(list, top);

            if (csv is not null)
                WriteCsv(csv, use, list);

            return 0;
        }
        catch (Exception ex) when (
            ex is ArgumentException
            or InvalidOperationException
            or UnauthorizedAccessException
            or NotSupportedException
            or Win32Exception
            or IOException
            or SecurityException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool TryRelaunchElevated(string[] args, out int exitCode)
    {
        exitCode = 1;
        string? fileName = Environment.ProcessPath;
        if (string.IsNullOrEmpty(fileName))
            throw new InvalidOperationException(
                "Cannot determine executable path to relaunch elevated.");

        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        psi.ArgumentList.Add($"--internal-attach-console={Environment.ProcessId}");
        foreach (string a in args)
            psi.ArgumentList.Add(a);

        Process? proc;
        try
        {
            proc = Process.Start(psi);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED
        {
            return false;
        }

        if (proc is null)
            throw new InvalidOperationException("Failed to start the elevated process.");

        using (proc)
        {
            Console.CancelKeyPress += static (_, e) => e.Cancel = true;
            proc.WaitForExit();
            exitCode = proc.ExitCode;
            return true;
        }
    }

    private static void AttachToConsole(uint pid)
    {
        Native.FreeConsole();
        if (!Native.AttachConsole(pid))
            Native.AllocConsole();

        IntPtr hin = Native.CreateFileW(
            "CONIN$",
            Native.GenericRead | Native.GenericWrite,
            Native.FileShareRead | Native.FileShareWrite,
            IntPtr.Zero,
            Native.OpenExisting,
            0,
            IntPtr.Zero);
        IntPtr hout = Native.CreateFileW(
            "CONOUT$",
            Native.GenericRead | Native.GenericWrite,
            Native.FileShareRead | Native.FileShareWrite,
            IntPtr.Zero,
            Native.OpenExisting,
            0,
            IntPtr.Zero);

        if (hin != Native.InvalidHandleValue)
            Native.SetStdHandle(Native.StdInputHandle, hin);
        if (hout != Native.InvalidHandleValue)
        {
            Native.SetStdHandle(Native.StdOutputHandle, hout);
            Native.SetStdHandle(Native.StdErrorHandle, hout);
        }

        Console.SetIn(new StreamReader(Console.OpenStandardInput()));
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), Console.OutputEncoding) { AutoFlush = true });
        Console.SetError(new StreamWriter(Console.OpenStandardError(), Console.OutputEncoding) { AutoFlush = true });
    }

    private const ulong OneGiBInPages = 1024UL * 1024 * 1024 / 4096;

    private static void PrintUse(ulong[] use, ulong totalPages, bool top)
    {
        Console.WriteLine($"{"Use",-18} {"Pages",16} {"Bytes",18} {"GiB",10}");
        Console.WriteLine(new string('-', 66));

        var rows = new List<(string Name, ulong Pages, string Suffix)>(Superfetch.UseNames.Length + 1);
        for (int i = 0; i < Superfetch.UseNames.Length; i++)
        {
            string suffix = i == Superfetch.UseDriverLocked ? "  <== guest RAM / locked MDLs" : "";
            rows.Add((Superfetch.UseNames[i], use[i], suffix));
        }

        ulong other = 0;
        for (int i = Superfetch.UseNames.Length; i < use.Length; i++)
            other += use[i];
        if (other != 0)
            rows.Add(("Other", other, ""));

        PrintCategoryRows(rows, top);

        Console.WriteLine(new string('-', 66));
        Console.WriteLine($"{"Total scanned",-18} {totalPages,16:N0} {totalPages * 4096UL,18:N0} {GiB(totalPages),10:N3}");
    }

    private static void PrintList(ulong[] list, bool top)
    {
        Console.WriteLine($"{"List",-18} {"Pages",16} {"Bytes",18} {"GiB",10}");
        Console.WriteLine(new string('-', 66));

        var rows = new List<(string Name, ulong Pages, string Suffix)>(Superfetch.ListNames.Length);
        for (int i = 0; i < Superfetch.ListNames.Length; i++)
            rows.Add((Superfetch.ListNames[i], list[i], ""));

        PrintCategoryRows(rows, top);
    }

    private static void PrintCategoryRows(
        List<(string Name, ulong Pages, string Suffix)> rows, bool top)
    {
        IEnumerable<(string Name, ulong Pages, string Suffix)> output = rows;
        if (top)
        {
            output = rows
                .Where(r => r.Pages >= OneGiBInPages)
                .OrderByDescending(r => r.Pages);
        }

        foreach (var (name, pages, suffix) in output)
        {
            Console.WriteLine(
                $"{name,-18} {pages,16:N0} {pages * 4096UL,18:N0} {GiB(pages),10:N3}{suffix}");
        }
    }

    private static void WriteCsv(string path, ulong[] use, ulong[] list)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(false));
        w.WriteLine("Kind,Name,Pages,Bytes");
        for (int i = 0; i < Superfetch.UseNames.Length; i++)
            w.WriteLine($"Use,{Superfetch.UseNames[i]},{use[i]},{use[i] * 4096UL}");
        for (int i = 0; i < Superfetch.ListNames.Length; i++)
            w.WriteLine($"List,{Superfetch.ListNames[i]},{list[i]},{list[i] * 4096UL}");
        Console.Error.WriteLine($"Wrote {path}");
    }

    private static double GiB(ulong pages) => pages * 4096.0 / (1024.0 * 1024.0 * 1024.0);
}
