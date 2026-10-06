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
//   Pfn --files          (per-file RAM use, clipped to the console window)
//   Pfn --files --all    (every file)
//   Pfn --most           (every file that prints as at least 0.001 GiB)

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
    internal const int UseMappedFile = 1;
    internal const int UseMetafile = 8;

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
        Dictionary<ulong, ulong[]>? files,
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
                    if (files is not null && use is UseMappedFile or UseMetafile)
                    {
                        // MMPFN_IDENTITY.u2 = FileObject / UniqueFileObjectKey
                        // (low bits carry flags such as Image).
                        // Counts layout: [list] for Mapped File, then
                        // [ListNames.Length + list] for Metafile.
                        ulong key = FileNames.NormalizeKey(ReadUIntPtr(req, ident + 16));
                        if (!files.TryGetValue(key, out var counts))
                        {
                            counts = new ulong[ListNames.Length * 2];
                            files[key] = counts;
                        }
                        if ((uint)list < (uint)ListNames.Length)
                            counts[(use == UseMetafile ? ListNames.Length : 0) + list]++;
                    }
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
            bool files = false;
            bool all = false;
            bool debug = false;
            bool most = false;
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
                else if (a is "-f" or "--files")
                    files = true;
                else if (a is "-a" or "--all")
                    all = true;
                else if (a is "-d" or "--debug")
                    debug = true;
                else if (a is "-m" or "--most")
                    most = true;
                else if (a.StartsWith("--csv=", StringComparison.OrdinalIgnoreCase))
                    csv = a[6..];
                else if (a == "--csv")
                    throw new ArgumentException("Use --csv=<file>");
                else
                    throw new ArgumentException($"Unknown switch: {a}");
            }

            if (most)
                all = true;
            if (all || debug)
                files = true;

            if (attachPid != 0)
                AttachToConsole(attachPid);

            if (help)
            {
                Console.WriteLine("""
                    Pfn — physical page use counts (RAMMap Use Counts, CLI)

                    Usage:
                      Pfn [--csv=<file>] [--quiet] [--top] [--files [--all] [--most] [--debug]]

                    Walks every physical page via Superfetch (same source RAMMap
                    uses). Needs elevation; an unelevated launch prompts UAC.
                    On a large machine this takes a while.

                    -t, --top   Omit categories under 1 GiB and sort each
                                section by size, largest first.

                    -f, --files List files with pages in RAM (Active, Standby,
                                Modified), largest first, like RAMMap's File
                                Summary. Names come from a short kernel ETW
                                file rundown. The list is cut to fit the
                                visible console window unless --all is given
                                or output is redirected.

                    -a, --all   With --files: list every file (implies --files).

                    -m, --most  Like --all, but omit files that would print as
                                0.000 GiB (under 0.0005 GiB in memory), i.e.
                                the long tail of tiny files (implies --all and
                                --files). Header totals and --csv still cover
                                all files.

                    -d, --debug With --files: show ETW session statistics
                                (events / buffers lost) and split unresolved
                                file objects by use type (implies --files).

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

            // When the file table must fit the window, count every row we
            // print from here on (stderr status lines included).
            LineCounter? lineCounter = null;
            if (files && !all && ConsoleWindow.VisibleSize() is { } win)
            {
                lineCounter = new LineCounter(win.Columns);
                Console.SetOut(new CountingWriter(Console.Out, lineCounter));
                Console.SetError(new CountingWriter(Console.Error, lineCounter));
            }

            Console.Error.WriteLine("Querying physical ranges...");
            PhysRange[] ranges = Superfetch.QueryRanges();
            ulong pages = 0;
            foreach (var r in ranges)
                pages += r.PageCount;
            Console.Error.WriteLine(
                $"  {ranges.Length} range(s), {pages:N0} pages ({GiB(pages):N2} GiB).");

            var use = new ulong[16];
            var list = new ulong[8];
            var fileCounts = files ? new Dictionary<ulong, ulong[]>() : null;
            DateTime last = DateTime.MinValue;
            Superfetch.Classify(ranges, use, list, fileCounts, (done, total) =>
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

            List<FileRow>? fileRows = null;
            RundownStats etwStats = default;
            if (fileCounts is not null)
            {
                if (!quiet)
                {
                    Console.Error.WriteLine("Resolving file names (kernel ETW file rundown)...");
                    Console.Error.WriteLine();
                }
                var names = FileNames.Collect(out etwStats);
                fileRows = BuildFileRows(fileCounts, names, splitUnresolved: debug);
            }

            PrintUse(use, pages, top);
            Console.WriteLine();
            PrintList(list, top);

            if (fileRows is not null)
            {
                Console.WriteLine();
                if (debug)
                {
                    // Printed before PrintFiles so the line counter budgets for it.
                    Console.WriteLine(
                        $"[debug] ETW {etwStats.Session}: {etwStats.NamesCollected:N0} names, " +
                        $"events lost {etwStats.EventsLost:N0}, log buffers lost {etwStats.LogBuffersLost:N0}, " +
                        $"{etwStats.BuffersWritten:N0} buffers written " +
                        $"({etwStats.BufferSizeKB:N0} KB, max {etwStats.MaximumBuffers:N0})");
                }
                PrintFiles(fileRows, lineCounter, most ? MostMinPages : 0);
            }

            if (csv is not null)
                WriteCsv(csv, use, list, fileRows);

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

    // --most omits files that would print as 0.000 GiB. 0.0005 GiB is 131.072
    // pages, so the cut-off is 132 pages (~528 KiB): 131 pages displays as
    // 0.000, 132 pages as 0.001.
    private const double MostThresholdGiB = 0.0005;
    private static readonly ulong MostMinPages = (ulong)Math.Ceiling(MostThresholdGiB * OneGiBInPages);

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

    private sealed record FileRow(string Name, ulong Active, ulong Standby, ulong Modified, ulong Total, bool Resolved);

    private static readonly FileRow EmptyRow = new("", 0, 0, 0, 0, false);

    private static FileRow Sum(FileRow a, FileRow b) => a with
    {
        Active = a.Active + b.Active,
        Standby = a.Standby + b.Standby,
        Modified = a.Modified + b.Modified,
        Total = a.Total + b.Total,
    };

    /// <summary>
    /// Totals for one use type of a key's counts array
    /// (half 0 = Mapped File, half 1 = Metafile; see Superfetch.Classify).
    /// </summary>
    private static FileRow Half(ulong[] c, int half)
    {
        const int standby = 2, modified = 3, modifiedNoWrite = 4, active = 6;
        int n = Superfetch.ListNames.Length;
        int o = half * n;
        ulong total = 0;
        for (int i = 0; i < n; i++)
            total += c[o + i];
        return EmptyRow with
        {
            Active = c[o + active],
            Standby = c[o + standby],
            Modified = c[o + modified] + c[o + modifiedNoWrite],
            Total = total,
        };
    }

    private static string Plural(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n:N0} {noun}s";

    private static List<FileRow> BuildFileRows(
        Dictionary<ulong, ulong[]> counts, Dictionary<ulong, string> names, bool splitUnresolved)
    {
        var rows = new List<FileRow>(counts.Count);

        // Unresolved tallies per use type: [0] = Mapped File, [1] = Metafile.
        string[] useLabel = ["Mapped File", "Metafile"];
        FileRow[] unresolved = [EmptyRow, EmptyRow];
        int[] unresolvedObjects = [0, 0];

        foreach (var (key, c) in counts)
        {
            FileRow mapped = Half(c, 0);
            FileRow meta = Half(c, 1);
            if (key != 0 && names.TryGetValue(key, out var name))
            {
                rows.Add(Sum(mapped, meta) with { Name = name, Resolved = true });
                continue;
            }

            FileRow[] halves = [mapped, meta];
            for (int h = 0; h < 2; h++)
            {
                if (halves[h].Total == 0)
                    continue;
                unresolved[h] = Sum(unresolved[h], halves[h]);
                unresolvedObjects[h]++;
            }
        }

        // The same file can appear under several keys (e.g. data vs. image
        // section); merge by name so each file is listed once.
        var merged = new Dictionary<string, FileRow>(rows.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
            merged[r.Name] = merged.TryGetValue(r.Name, out var m) ? Sum(m, r) : r;
        rows = [.. merged.Values];

        if (splitUnresolved)
        {
            for (int h = 0; h < 2; h++)
            {
                if (unresolved[h].Total != 0)
                {
                    rows.Add(unresolved[h] with
                    {
                        Name = $"<{Plural(unresolvedObjects[h], $"unresolved {useLabel[h]} object")}>",
                    });
                }
            }
        }
        else
        {
            FileRow all = Sum(unresolved[0], unresolved[1]);
            if (all.Total != 0)
            {
                // Metafile pages here are file-system metadata streams (NTFS,
                // ReFS, ...) that the kernel rundown reports without a name -
                // expected. Mapped File pages are genuine misses (typically a
                // file closed between the page scan and the rundown). Say which
                // is which without spending a second line.
                int meta = unresolvedObjects[1];
                int file = unresolvedObjects[0];
                string label = (meta, file) switch
                {
                    (_, 0) => $"<{Plural(meta, "unnamed file-system metadata stream")}>",
                    (0, _) => $"<{Plural(file, "unresolved file object")}>",
                    _ => $"<{Plural(meta, "unnamed metadata stream")} + {Plural(file, "unresolved file")}>",
                };
                rows.Add(all with { Name = label });
            }
        }

        rows.Sort((a, b) => b.Total.CompareTo(a.Total));
        return rows;
    }

    private static void PrintFiles(List<FileRow> rows, LineCounter? lineCounter, ulong minPages)
    {
        // Header totals always describe everything in memory, even with --most.
        ulong total = 0, resolved = 0;
        foreach (var r in rows)
        {
            total += r.Total;
            if (r.Resolved)
                resolved += r.Total;
        }
        int fileCount = rows.Count(r => r.Resolved);
        double pct = total == 0 ? 100 : 100.0 * resolved / total;

        // Rows are sorted largest first, so --most keeps a prefix of the list.
        int eligible = rows.Count;
        if (minPages > 0)
        {
            eligible = rows.FindIndex(r => r.Total < minPages);
            if (eligible < 0)
                eligible = rows.Count;
        }

        // Prefix: four 9-wide columns, single spaces between, two before path.
        const int prefixWidth = 9 * 4 + 3 + 2;

        int limit = eligible;
        int pathWidth = int.MaxValue;
        if (lineCounter is not null && ConsoleWindow.VisibleSize() is { } s)
        {
            // Everything this run puts on screen must fit in the window:
            //   1  the command line that launched us
            //   N  rows already printed (status lines, category tables)
            //   4  title, blank line, column header, rule
            //   2  blank line + "... more not shown" line
            //   2  shell's blank line + next prompt
            int left = s.Rows - 1 - lineCounter.RowsUsed - 4 - 2 - 2;
            limit = Math.Clamp(left, 0, eligible);
            pathWidth = Math.Max(20, s.Columns - prefixWidth - 1);
        }

        Console.WriteLine(
            $"Files in memory: {fileCount:N0} files, {GiB(total):N3} GiB file-backed " +
            $"({pct:N1}% resolved to a name)");
        Console.WriteLine();
        Console.WriteLine($"{"Total GiB",9} {"Active",9} {"Standby",9} {"Modified",9}  File");
        Console.WriteLine(new string('-', 66));
        for (int i = 0; i < limit; i++)
        {
            var r = rows[i];
            Console.WriteLine(
                $"{GiB(r.Total),9:N3} {GiB(r.Active),9:N3} {GiB(r.Standby),9:N3} {GiB(r.Modified),9:N3}  " +
                ClipLeft(r.Name, pathWidth));
        }

        int hidden = eligible - limit;          // didn't fit in the window
        int omitted = rows.Count - eligible;    // below the --most threshold
        if (hidden > 0 || omitted > 0)
        {
            var parts = new List<string>(3);
            if (hidden > 0)
            {
                string hint = limit == 0 ? " (window too small)" : "";
                parts.Add($"{hidden:N0} more ({GiB(SumTotal(rows, limit, eligible)):N3} GiB) not shown{hint}");
            }
            if (omitted > 0)
            {
                parts.Add(
                    $"{Plural(omitted, "file")} under {MostThresholdGiB} GiB " +
                    $"({GiB(SumTotal(rows, eligible, rows.Count)):N3} GiB) omitted");
            }
            if (hidden > 0)
                parts.Add("use --all to list everything");

            Console.WriteLine();
            Console.WriteLine("... " + string.Join("; ", parts) + ".");
        }
    }

    private static ulong SumTotal(List<FileRow> rows, int from, int to)
    {
        ulong sum = 0;
        for (int i = from; i < to; i++)
            sum += rows[i].Total;
        return sum;
    }

    /// <summary>
    /// Shortens a path to <paramref name="width"/> characters while always
    /// keeping its root (E:\, \\server\share\, \Device\X\): the middle is
    /// replaced by "...", and the kept tail starts at a folder boundary when
    /// that still leaves something meaningful.
    /// </summary>
    private static string ClipLeft(string s, int width)
    {
        if (s.Length <= width)
            return s;

        string root = PathRoot(s);
        const string ellipsis = "...";
        int tailLen = width - root.Length - ellipsis.Length;
        if (root.Length == 0 || tailLen < 8)
            return string.Concat(ellipsis, s.AsSpan(s.Length - (width - ellipsis.Length)));

        // Result is root + "..." + tail, where tail begins with a backslash.
        ReadOnlySpan<char> tail = s.AsSpan(s.Length - tailLen);
        int sep = tail.IndexOf('\\');
        string tailText = sep >= 0 && tail.Length - sep > tailLen / 2
            ? tail[sep..].ToString()
            : string.Concat("\\", tail[1..]);

        return string.Concat(root, ellipsis, tailText);
    }

    /// <summary>Root of a path including its trailing backslash, or "" if none.</summary>
    private static string PathRoot(string s)
    {
        // Drive letter: E:\
        if (s.Length >= 3 && s[1] == ':' && s[2] == '\\')
            return s[..3];

        // UNC (\\server\share\) or NT device path (\Device\Name\): keep up to
        // and including the backslash that ends the share / device name.
        int needed = s.StartsWith(@"\\", StringComparison.Ordinal) ? 4
            : s.StartsWith('\\') ? 3
            : 0;
        int idx = -1;
        for (int i = 0; i < needed; i++)
        {
            idx = s.IndexOf('\\', idx + 1);
            if (idx < 0)
                return "";
        }
        return needed == 0 ? "" : s[..(idx + 1)];
    }

    private static void WriteCsv(string path, ulong[] use, ulong[] list, List<FileRow>? files)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(false));
        w.WriteLine("Kind,Name,Pages,Bytes,ActivePages,StandbyPages,ModifiedPages");
        for (int i = 0; i < Superfetch.UseNames.Length; i++)
            w.WriteLine($"Use,{Superfetch.UseNames[i]},{use[i]},{use[i] * 4096UL},,,");
        for (int i = 0; i < Superfetch.ListNames.Length; i++)
            w.WriteLine($"List,{Superfetch.ListNames[i]},{list[i]},{list[i] * 4096UL},,,");
        if (files is not null)
        {
            foreach (var f in files)
            {
                string name = "\"" + f.Name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
                w.WriteLine($"File,{name},{f.Total},{f.Total * 4096UL},{f.Active},{f.Standby},{f.Modified}");
            }
        }
        Console.Error.WriteLine($"Wrote {path}");
    }

    private static double GiB(ulong pages) => pages * 4096.0 / (1024.0 * 1024.0 * 1024.0);
}
