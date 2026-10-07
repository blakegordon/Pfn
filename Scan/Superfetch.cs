using PfnUseDump.NameResolution;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PfnUseDump.Scan;

/// <summary>
/// Physical memory ranges and per-page (PFN) classification via the
/// undocumented SystemSuperfetchInformation class of NtQuerySystemInformation.
/// </summary>
internal static partial class Superfetch
{
    private const int SystemSuperfetchInformation = 79;
    private const int SuperfetchPfnQuery = 6;
    private const int SuperfetchMemoryRangesQuery = 17;

    private const uint SuperfetchVersion = 45;
    private const uint SuperfetchMagic = 0x6B756843; // 'kuhC'

    private const int StatusBufferTooSmall = unchecked((int)0xC0000023);
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    private const uint SeProfileSingleProcessPrivilege = 13;

    private const uint QueryMemoryList = 1;

    // A PFN query request is a PfnRequestHeader, then the 176-byte
    // SYSTEM_MEMORY_LIST_INFORMATION (which we don't read), then the
    // MmpfnIdentity array that the kernel fills in.
    private const int PfnPagesOffset = 0xC0;
    private const int BatchPages = 16_384;

    // MMPFN_IDENTITY.u1.e1.UseDescription is the low 4 bits.
    // ListDescription is the next 3 bits.
    internal const int UseDriverLocked = 10;
    internal const int UseMappedFile = 1;
    internal const int UseMetafile = 8;

    internal const int ListStandby = 2;

    /// <summary>Page priorities run 0-7; Windows reuses low-priority Standby pages first.</summary>
    internal const int PriorityLevels = 8;

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
        int st = RtlAdjustPrivilege(
            SeProfileSingleProcessPrivilege,
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

    private static PhysRange[] QueryRangesVersion(uint version)
    {
        // V1 reply header: ULONG Version, ULONG RangeCount.
        // V2 reply header: ULONG Version, ULONG Flags, SIZE_T RangeCount.
        int headerSize = version == 2 ? 16 : 8;
        byte[] buf = new byte[headerSize + 8];
        BitConverter.TryWriteBytes(buf, version);

        int status = Query(SuperfetchMemoryRangesQuery, buf, out uint needed);
        if (status is StatusBufferTooSmall or StatusInfoLengthMismatch)
        {
            if (needed < 32)
                needed = 4096;
            buf = new byte[needed];
            BitConverter.TryWriteBytes(buf, version);
            status = Query(SuperfetchMemoryRangesQuery, buf, out _);
        }

        if (status < 0)
            throw new InvalidOperationException(
                $"SuperfetchMemoryRangesQuery v{version} failed: 0x{status:X8}");

        int rangeCount = version == 2
            ? (int)BitConverter.ToUInt64(buf, 8)
            : (int)BitConverter.ToUInt32(buf, 4);

        // The ranges follow the header, laid out exactly like PhysRange.
        return MemoryMarshal.Cast<byte, PhysRange>(buf.AsSpan(headerSize))[..rangeCount].ToArray();
    }

    public static void Classify(
        PhysRange[] ranges,
        ulong[] useCounts,
        ulong[] listCounts,
        ulong[] standbyByPriority,
        Dictionary<ulong, ulong[]>? files,
        Action<ulong, ulong>? progress)
    {
        byte[] req = new byte[PfnPagesOffset + Unsafe.SizeOf<MmpfnIdentity>() * BatchPages];

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
                var header = new PfnRequestHeader { Version = 1, RequestFlags = QueryMemoryList, PfnCount = (ulong)batch };
                MemoryMarshal.Write(req, in header);

                Span<MmpfnIdentity> pages = MemoryMarshal.Cast<byte, MmpfnIdentity>(req.AsSpan(PfnPagesOffset))[..batch];
                for (int i = 0; i < batch; i++)
                    pages[i].PageFrameIndex = pfn + (ulong)i;

                int status = Query(SuperfetchPfnQuery, req, out _);
                if (status < 0)
                    throw new InvalidOperationException(
                        $"SuperfetchPfnQuery failed: 0x{status:X8} (PFN 0x{pfn:X})");

                foreach (MmpfnIdentity page in pages)
                {
                    int use = page.UseDescription;
                    int list = page.ListDescription;
                    if ((uint)use < (uint)useCounts.Length)
                        useCounts[use]++;
                    if ((uint)list < (uint)listCounts.Length)
                        listCounts[list]++;
                    if (list == ListStandby)
                        standbyByPriority[page.Priority]++;
                    if (files is not null && use is UseMappedFile or UseMetafile)
                    {
                        // Counts layout: [list] for Mapped File, then
                        // [ListNames.Length + list] for Metafile.
                        ulong key = FileNames.NormalizeKey(page.U2);
                        if (!files.TryGetValue(key, out var counts))
                        {
                            counts = new ulong[ListNames.Length * 2];
                            files[key] = counts;
                        }
                        if ((uint)list < (uint)ListNames.Length)
                            counts[(use == UseMetafile ? ListNames.Length : 0) + list]++;
                    }
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
                Version = SuperfetchVersion,
                Magic = SuperfetchMagic,
                InfoClass = infoClass,
                Data = pin.AddrOfPinnedObject(),
                Length = (uint)data.Length,
            };
            return NtQuerySystemInformation(
                SystemSuperfetchInformation, ref header, (uint)Unsafe.SizeOf<SuperfetchHeader>(), out returnLength);
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

    /// <summary>PF_PFN_PRIO_REQUEST, up to (not including) its memory-list statistics.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PfnRequestHeader
    {
        public uint Version;
        public uint RequestFlags;
        public ulong PfnCount;
    }

    /// <summary>MMPFN_IDENTITY: we fill in PageFrameIndex; the kernel fills in U1 and U2.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MmpfnIdentity
    {
        public ulong U1;
        public ulong PageFrameIndex;

        /// <summary>For file pages, the file object key (low bits carry flags such as Image).</summary>
        public ulong U2;

        public readonly int UseDescription => (int)(U1 & 0xF);

        public readonly int ListDescription => (int)((U1 >> 4) & 0x7);

        public readonly int Priority => (int)((U1 >> 57) & 0x7);
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtQuerySystemInformation(
        int systemInformationClass,
        ref SuperfetchHeader systemInformation,
        uint systemInformationLength,
        out uint returnLength);

    [LibraryImport("ntdll.dll")]
    private static partial int RtlAdjustPrivilege(
        uint privilege,
        [MarshalAs(UnmanagedType.U1)] bool enable,
        [MarshalAs(UnmanagedType.U1)] bool currentThread,
        [MarshalAs(UnmanagedType.U1)] out bool previous);
}
