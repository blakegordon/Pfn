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

    // EVENT_TRACE_PROPERTIES (x64) is 120 bytes; names follow it in our buffer.
    private const int PropsSize = 120;
    private const int LoggerNameBytes = 1024;
    private const int LogFileNameBytes = 2048;
    private const int PropsTotal = PropsSize + LoggerNameBytes + LogFileNameBytes;

    // EVENT_TRACE_LOGFILEW (x64) is 448 bytes.
    private const int LogFileStructSize = 448;

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
        IntPtr props = Marshal.AllocHGlobal(PropsTotal);
        try
        {
            InitProperties(props, sessionGuid, systemLogger, etlPath);
            int err = StartTraceW(out ulong handle, loggerName, props);

            if (err == ErrorAlreadyExists && systemLogger)
            {
                // A stale session with our (PID-unique) name: stop it and retry.
                InitProperties(props, sessionGuid, systemLogger, etlPath);
                _ = ControlTraceW(0, loggerName, props, EventTraceControlStop);
                InitProperties(props, sessionGuid, systemLogger, etlPath);
                err = StartTraceW(out handle, loggerName, props);
            }

            if (err != ErrorSuccess)
                return err;

            // Stopping the session is what triggers the FileRundown events.
            // On return, ControlTrace fills in the final session statistics.
            InitProperties(props, sessionGuid, systemLogger, etlPath);
            err = ControlTraceW(handle, null, props, EventTraceControlStop);
            if (err == ErrorSuccess)
            {
                byte* b = (byte*)props;
                stats = new RundownStats(
                    EventsLost: *(uint*)(b + 88),
                    BuffersWritten: *(uint*)(b + 92),
                    LogBuffersLost: *(uint*)(b + 96),
                    BufferSizeKB: *(uint*)(b + 48),
                    MaximumBuffers: *(uint*)(b + 56),
                    NamesCollected: 0,
                    Session: "");
            }
            return err;
        }
        finally
        {
            Marshal.FreeHGlobal(props);
        }
    }

    private static void InitProperties(IntPtr p, Guid sessionGuid, bool systemLogger, string etlPath)
    {
        new Span<byte>((void*)p, PropsTotal).Clear();
        byte* b = (byte*)p;

        // WNODE_HEADER
        *(uint*)(b + 0) = PropsTotal;                    // BufferSize
        *(Guid*)(b + 24) = sessionGuid;                  // Guid
        *(uint*)(b + 40) = 1;                            // ClientContext = QPC
        *(uint*)(b + 44) = WnodeFlagTracedGuid;          // Flags

        // The rundown emits one event per file object (600k+ on a large-cache
        // machine) in a single burst at session stop. Give the logger enough
        // buffer space to absorb it while the file writer catches up; buffers
        // are only allocated on demand, up to MaximumBuffers.
        *(uint*)(b + 48) = EtwBufferSizeKB;              // BufferSize (KB)
        *(uint*)(b + 52) = EtwMinimumBuffers;            // MinimumBuffers
        *(uint*)(b + 56) = EtwMaximumBuffers;            // MaximumBuffers
        *(uint*)(b + 64) = EventTraceFileModeSequential | (systemLogger ? EventTraceSystemLoggerMode : 0); // LogFileMode
        *(uint*)(b + 72) = EventTraceFlagDiskIo | EventTraceFlagDiskFileIo; // EnableFlags
        *(uint*)(b + 112) = PropsSize + LoggerNameBytes; // LogFileNameOffset
        *(uint*)(b + 116) = PropsSize;                   // LoggerNameOffset

        var dst = new Span<char>(b + PropsSize + LoggerNameBytes, LogFileNameBytes / 2 - 1);
        etlPath.AsSpan(0, Math.Min(etlPath.Length, dst.Length)).CopyTo(dst);
    }

    private static Dictionary<ulong, string> ReadRundown(string etlPath)
    {
        var names = new Dictionary<ulong, string>();
        s_names = names;
        s_callbackFailure = null;

        IntPtr logFile = Marshal.AllocHGlobal(LogFileStructSize);
        IntPtr pathPtr = Marshal.StringToHGlobalUni(etlPath);
        try
        {
            new Span<byte>((void*)logFile, LogFileStructSize).Clear();
            byte* b = (byte*)logFile;
            *(IntPtr*)(b + 0) = pathPtr;                               // LogFileName
            *(uint*)(b + 28) = ProcessTraceModeEventRecord;            // ProcessTraceMode
            *(IntPtr*)(b + 424) = (IntPtr)(delegate* unmanaged<IntPtr, void>)&OnEvent; // EventRecordCallback

            ulong h = OpenTraceW(logFile);
            if (h == InvalidProcessTraceHandle)
                throw new InvalidOperationException(
                    $"OpenTrace on {etlPath} failed: {Marshal.GetLastPInvokeError()}");
            try
            {
                int err = ProcessTrace(&h, 1, IntPtr.Zero, IntPtr.Zero);
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
            Marshal.FreeHGlobal(logFile);
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
    private static void OnEvent(IntPtr record)
    {
        var names = s_names;
        if (names is null || s_callbackFailure is not null)
            return;

        try
        {
            // EVENT_RECORD (x64):
            //   +0x00 EVENT_HEADER (80): Flags @4, ProviderId @24, Opcode @45
            //   +0x56 UserDataLength (USHORT)
            //   +0x60 UserData (PVOID)
            byte* r = (byte*)record;
            ushort flags = *(ushort*)(r + 4);
            Guid provider = *(Guid*)(r + 24);
            byte opcode = *(r + 45);
            if (provider != FileIoGuid)
                return;
            if (opcode is not (OpcodeName or OpcodeFileCreate or OpcodeFileRundown))
                return;

            int len = *(ushort*)(r + 86);
            byte* data = *(byte**)(r + 96);
            int ptrSize = (flags & EventHeaderFlag32BitHeader) != 0 ? 4 : 8;
            if (data == null || len <= ptrSize)
                return;

            ulong key = ptrSize == 8 ? *(ulong*)data : *(uint*)data;
            int chars = (len - ptrSize) / 2;
            var span = new ReadOnlySpan<char>(data + ptrSize, chars);
            int nul = span.IndexOf('\0');
            if (nul >= 0)
                span = span[..nul];
            if (span.IsEmpty)
                return;

            // Rundown is authoritative; don't let an older Name event override it.
            ulong norm = NormalizeKey(key);
            if (opcode == OpcodeFileRundown || !names.ContainsKey(norm))
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
    private static partial int StartTraceW(out ulong traceHandle, string instanceName, IntPtr properties);

    [LibraryImport("advapi32.dll", EntryPoint = "ControlTraceW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int ControlTraceW(ulong traceHandle, string? instanceName, IntPtr properties, uint controlCode);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenTraceW", SetLastError = true)]
    private static partial ulong OpenTraceW(IntPtr logfile);

    [LibraryImport("advapi32.dll")]
    private static partial int ProcessTrace(ulong* handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [LibraryImport("advapi32.dll")]
    private static partial int CloseTrace(ulong traceHandle);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, uint ucchMax);
}
