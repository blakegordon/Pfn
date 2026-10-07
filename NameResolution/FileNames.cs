using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace PfnUseDump.NameResolution;

// FileNames — resolves the file-object keys that SuperfetchPfnQuery reports for
// mapped-file / metafile pages into path names.
//
// User mode cannot read a FILE_OBJECT, so (like RAMMap and System Informer) we
// start a short-lived kernel ETW session with the DISK_FILE_IO ("FILENAME")
// flag. When that session stops, the kernel emits a FileIo "FileRundown" event
// (opcode 36) for every file object it knows about, carrying the object key and
// its \Device\HarddiskVolumeN\... path. We log to a temporary .etl file, stop the
// session, then read the file back.
internal static unsafe partial class FileNames
{
    // FileIo provider GUID (classic kernel MOF class).
    private static readonly Guid FileIoGuid = new("90cbdc39-4a3e-11d1-84f4-0000f80464e3");
    private static readonly Guid SystemTraceControlGuid = new("9e814aad-3204-11d2-9a82-006008a86939");

    private const string KernelLoggerName = "NT Kernel Logger";

    private const uint WnodeFlagTracedGuid = 0x00020000;
    private const uint EventTraceFileModeSequential = 0x00000001;
    private const uint EventTraceSystemLoggerMode = 0x02000000;
    private const uint EventTraceFlagDiskIo = 0x00000100;
    private const uint EventTraceFlagDiskFileIo = 0x00000200;
    private const uint EventTraceControlStop = 1;
    private const uint ProcessTraceModeEventRecord = 0x10000000;
    private const ushort EventHeaderFlag32BitHeader = 0x0020;

    private const byte OpcodeName = 0;
    private const byte OpcodeFileCreate = 32;
    private const byte OpcodeFileRundown = 36;

    private const int ErrorSuccess = 0;
    private const int ErrorAlreadyExists = 183;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorCancelled = 1223;

    // sizeof(EVENT_TRACE_PROPERTIES) on x64: the fields of TraceProperties
    // before its two name buffers.
    private const uint EventTracePropertiesSize = 120;

    // Session buffers: 1 MB each (the documented maximum), 64 preallocated,
    // growing on demand to 256 (~256 MB of nonpaged pool, only while the
    // rundown burst is in flight). ETW may clamp these; --debug shows the
    // values the kernel actually used.
    private const uint EtwBufferSizeKB = 1024;
    private const uint EtwMinimumBuffers = 64;
    private const uint EtwMaximumBuffers = 256;

    private static readonly ulong InvalidProcessTraceHandle = ulong.MaxValue;

    // Filled by the ETW callback (ProcessTrace runs callbacks on the calling thread).
    private static Dictionary<ulong, string>? s_names;

    // First exception raised inside OnEvent; rethrown after ProcessTrace returns.
    private static ExceptionDispatchInfo? s_callbackFailure;

    /// <summary>
    /// Masks off the low flag bits (e.g. the "Image" bit) so PFN keys and ETW
    /// keys compare equal. Kernel objects are at least 16-byte aligned.
    /// </summary>
    internal static ulong NormalizeKey(ulong key) => key & ~0xFUL;

    /// <summary>
    /// Returns a map of normalized file-object key to DOS-style path, plus the
    /// ETW session's loss counters (for --debug).
    /// </summary>
    public static Dictionary<ulong, string> Collect(out RundownStats stats)
    {
        string etl = Path.Combine(Path.GetTempPath(), $"Pfn-{Environment.ProcessId}.etl");
        try
        {
            stats = RecordRundown(etl);
            var raw = ReadRundown(etl);
            stats = stats with { NamesCollected = raw.Count };

            var devices = BuildDeviceMap();
            var result = new Dictionary<ulong, string>(raw.Count);
            foreach (var (key, path) in raw)
                result[key] = ToDosPath(path, devices);
            return result;
        }
        finally
        {
            try
            {
                File.Delete(etl);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static RundownStats RecordRundown(string etlPath)
    {
        // Prefer a private system logger (Windows 8+): it does not collide with
        // anything already using the single "NT Kernel Logger" session.
        string privateName = $"Pfn File Rundown {Environment.ProcessId}";
        int err = StartAndStop(privateName, Guid.NewGuid(), systemLogger: true, etlPath, out var stats);
        if (err == ErrorSuccess)
            return stats with { Session = "private system logger" };

        int err2 = StartAndStop(KernelLoggerName, SystemTraceControlGuid, systemLogger: false, etlPath, out stats);
        if (err2 == ErrorSuccess)
            return stats with { Session = KernelLoggerName };

        string hint = err2 == ErrorAlreadyExists
            ? " The NT Kernel Logger is in use by another tool (e.g. Process Monitor, xperf, WPR)."
            : "";
        throw new InvalidOperationException(
            $"Could not start a kernel ETW session for file names " +
            $"(system logger error {err}, NT Kernel Logger error {err2}).{hint}");
    }

    private static int StartAndStop(
        string loggerName, Guid sessionGuid, bool systemLogger, string etlPath, out RundownStats stats)
    {
        stats = default;
        var props = RundownSessionSettings(sessionGuid, systemLogger, etlPath);
        int err = StartTraceW(out ulong handle, loggerName, &props);

        if (err == ErrorAlreadyExists && systemLogger)
        {
            // A stale session with our (PID-unique) name: stop it and retry.
            props = RundownSessionSettings(sessionGuid, systemLogger, etlPath);
            _ = ControlTraceW(0, loggerName, &props, EventTraceControlStop);
            props = RundownSessionSettings(sessionGuid, systemLogger, etlPath);
            err = StartTraceW(out handle, loggerName, &props);
        }

        if (err != ErrorSuccess)
            return err;

        // Stopping the session is what triggers the FileRundown events.
        // On return, ControlTrace fills in the final session statistics.
        props = RundownSessionSettings(sessionGuid, systemLogger, etlPath);
        err = ControlTraceW(handle, null, &props, EventTraceControlStop);
        if (err == ErrorSuccess)
        {
            stats = new RundownStats(
                EventsLost: props.EventsLost,
                BuffersWritten: props.BuffersWritten,
                LogBuffersLost: props.LogBuffersLost,
                BufferSizeKB: props.BufferSize,
                MaximumBuffers: props.MaximumBuffers,
                NamesCollected: 0,
                Session: "");
        }
        return err;
    }

    /// <summary>
    /// Settings for the kernel ETW session that produces the file rundown:
    /// buffers, flags, and the .etl path.
    /// StartTrace and ControlTrace write back into the struct, so callers build
    /// a fresh one for each call.
    /// </summary>
    private static TraceProperties RundownSessionSettings(Guid sessionGuid, bool systemLogger, string etlPath)
    {
        var p = new TraceProperties
        {
            WnodeBufferSize = (uint)sizeof(TraceProperties),
            Guid = sessionGuid,
            ClientContext = 1, // QPC timestamps
            WnodeFlags = WnodeFlagTracedGuid,

            // The rundown emits one event per file object (600k+ on a large-cache
            // machine) in a single burst at session stop. Give the logger enough
            // buffer space to absorb it while the file writer catches up; buffers
            // are only allocated on demand, up to MaximumBuffers.
            BufferSize = EtwBufferSizeKB,
            MinimumBuffers = EtwMinimumBuffers,
            MaximumBuffers = EtwMaximumBuffers,
            LogFileMode = EventTraceFileModeSequential | (systemLogger ? EventTraceSystemLoggerMode : 0),
            EnableFlags = EventTraceFlagDiskIo | EventTraceFlagDiskFileIo,
            LoggerNameOffset = EventTracePropertiesSize,
            LogFileNameOffset = EventTracePropertiesSize + (uint)sizeof(NameBuffer),
        };
        etlPath.AsSpan(0, Math.Min(etlPath.Length, NameBuffer.Length - 1)).CopyTo(p.LogFileName);
        return p;
    }

    private static Dictionary<ulong, string> ReadRundown(string etlPath)
    {
        var names = new Dictionary<ulong, string>();
        s_names = names;
        s_callbackFailure = null;

        IntPtr pathPtr = Marshal.StringToHGlobalUni(etlPath);
        try
        {
            var logFile = new TraceLogFile
            {
                LogFileName = pathPtr,
                ProcessTraceMode = ProcessTraceModeEventRecord,
                EventRecordCallback = &OnEvent,
            };

            ulong h = OpenTraceW(ref logFile);
            if (h == InvalidProcessTraceHandle)
                throw new InvalidOperationException(
                    $"OpenTrace on {etlPath} failed: {Marshal.GetLastPInvokeError()}");
            try
            {
                int err = ProcessTrace(ref h, 1, IntPtr.Zero, IntPtr.Zero);
                // OnEvent (invoked by ProcessTrace) may have stashed a failure.
                Interlocked.Exchange(ref s_callbackFailure, null)?.Throw();
                if (err is not (ErrorSuccess or ErrorCancelled))
                    throw new InvalidOperationException($"ProcessTrace failed: {err}");
            }
            finally
            {
                _ = CloseTrace(h);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
            s_names = null;
            s_callbackFailure = null;
        }

        return names;
    }

    // ETW calls OnEvent from native code; an exception must not unwind through
    // ProcessTrace (that terminates the process). The body is written so that
    // only two failures are possible:
    //   OutOfMemoryException      - span.ToString() / dictionary growth
    //   InvalidOperationException - Dictionary's concurrent-use detection
    // (Bad pointers would raise AccessViolationException, which .NET cannot
    // catch anyway.) The first failure is stashed and rethrown by ReadRundown
    // once ProcessTrace returns; later events are ignored.
    [UnmanagedCallersOnly]
    private static void OnEvent(EventRecord* record)
    {
        var names = s_names;
        if (names is null || s_callbackFailure is not null)
            return;

        try
        {
            EventRecord e = *record;
            if (e.ProviderId != FileIoGuid)
                return;
            if (e.Opcode is not (OpcodeName or OpcodeFileCreate or OpcodeFileRundown))
                return;

            // The event data is the file-object key (pointer-sized), then the
            // NUL-terminated UTF-16 path.
            int keySize = (e.Flags & EventHeaderFlag32BitHeader) != 0 ? 4 : 8;
            if (e.UserData == null || e.UserDataLength <= keySize)
                return;
            var data = new ReadOnlySpan<byte>(e.UserData, e.UserDataLength);

            ulong key = keySize == 8 ? MemoryMarshal.Read<ulong>(data) : MemoryMarshal.Read<uint>(data);
            var span = MemoryMarshal.Cast<byte, char>(data[keySize..]);
            int nul = span.IndexOf('\0');
            if (nul >= 0)
                span = span[..nul];
            if (span.IsEmpty)
                return;

            // Rundown is authoritative; don't let an older Name event override it.
            ulong norm = NormalizeKey(key);
            if (e.Opcode == OpcodeFileRundown || !names.ContainsKey(norm))
                names[norm] = span.ToString();
        }
        catch (Exception ex) when (ex is OutOfMemoryException or InvalidOperationException)
        {
            s_callbackFailure = ExceptionDispatchInfo.Capture(ex);
        }
    }

    private static List<(string Device, string Dos)> BuildDeviceMap()
    {
        var map = new List<(string, string)>();
        char[] buf = new char[1024];
        for (char c = 'A'; c <= 'Z'; c++)
        {
            string drive = $"{c}:";
            uint n = QueryDosDeviceW(drive, buf, (uint)buf.Length);
            if (n == 0)
                continue;
            string target = new string(buf, 0, (int)n).Split('\0')[0];
            if (target.Length != 0)
                map.Add((target, drive));
        }
        // Longest device names first so \Device\HarddiskVolume1 doesn't match ...Volume10.
        map.Sort((a, b) => b.Item1.Length.CompareTo(a.Item1.Length));
        return map;
    }

    private static string ToDosPath(string ntPath, List<(string Device, string Dos)> devices)
    {
        foreach (var (device, dos) in devices)
        {
            if (ntPath.Length > device.Length &&
                ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                ntPath[device.Length] == '\\')
            {
                return string.Concat(dos, ntPath.AsSpan(device.Length));
            }
            if (ntPath.Equals(device, StringComparison.OrdinalIgnoreCase))
                return dos + "\\";
        }
        return ntPath;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "StartTraceW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int StartTraceW(out ulong traceHandle, string instanceName, TraceProperties* properties);

    [LibraryImport("advapi32.dll", EntryPoint = "ControlTraceW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int ControlTraceW(ulong traceHandle, string? instanceName, TraceProperties* properties, uint controlCode);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenTraceW", SetLastError = true)]
    private static partial ulong OpenTraceW(ref TraceLogFile logfile);

    [LibraryImport("advapi32.dll")]
    private static partial int ProcessTrace(ref ulong handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [LibraryImport("advapi32.dll")]
    private static partial int CloseTrace(ulong traceHandle);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, uint ucchMax);

    /// <summary>
    /// EVENT_TRACE_PROPERTIES (with its WNODE_HEADER flattened in), followed by
    /// room for the logger name and log file name that the API expects to find
    /// at LoggerNameOffset and LogFileNameOffset.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TraceProperties
    {
        public uint WnodeBufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint WnodeFlags;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
        public NameBuffer LoggerName;
        public NameBuffer LogFileName;
    }

    [InlineArray(Length)]
    private struct NameBuffer
    {
        public const int Length = 1024;
        private char _first;
    }

    /// <summary>EVENT_TRACE_LOGFILEW, naming only the fields we set.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TraceLogFile
    {
        public IntPtr LogFileName;
        public IntPtr LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        private fixed byte _currentEventAndLogfileHeader[88 + 280]; // EVENT_TRACE, TRACE_LOGFILE_HEADER
        public IntPtr BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public delegate* unmanaged<EventRecord*, void> EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    /// <summary>EVENT_RECORD, with its EVENT_HEADER and EVENT_DESCRIPTOR flattened in.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct EventRecord
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
        public ulong ProcessorTime;
        public Guid ActivityId;
        public uint BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public byte* UserData;
        public IntPtr UserContext;
    }
}
