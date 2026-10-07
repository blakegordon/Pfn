using PfnUseDump.NameResolution;
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

    private static PhysRange[] QueryRangesVersion(int version)
    {
        uint probe = (uint)(version == 2 ? 24 : 16);
        byte[] buf = new byte[probe];
        WriteUInt32(buf, 0, (uint)version);

        int status = Query(SuperfetchMemoryRangesQuery, buf, out uint needed);
        if (status is StatusBufferTooSmall or StatusInfoLengthMismatch)
        {
            if (needed < 32)
                needed = 4096;
            buf = new byte[needed];
            WriteUInt32(buf, 0, (uint)version);
            status = Query(SuperfetchMemoryRangesQuery, buf, out _);
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

                int status = Query(SuperfetchPfnQuery, req, out _);
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
                Version = SuperfetchVersion,
                Magic = SuperfetchMagic,
                InfoClass = infoClass,
                Data = pin.AddrOfPinnedObject(),
                Length = (uint)data.Length,
            };

            GCHandle hdr = GCHandle.Alloc(header, GCHandleType.Pinned);
            try
            {
                return NtQuerySystemInformation(
                    SystemSuperfetchInformation,
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

    [LibraryImport("ntdll.dll")]
    private static partial int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        uint systemInformationLength,
        out uint returnLength);

    [LibraryImport("ntdll.dll")]
    private static partial int RtlAdjustPrivilege(
        uint privilege,
        [MarshalAs(UnmanagedType.U1)] bool enable,
        [MarshalAs(UnmanagedType.U1)] bool currentThread,
        [MarshalAs(UnmanagedType.U1)] out bool previous);
}
