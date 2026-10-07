using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PfnUseDump.Terminal;

/// <summary>
/// UAC relaunch, both halves: the unelevated parent detects that it is not
/// elevated and starts an elevated copy of itself (<see cref="TryRelaunch"/>),
/// passing <see cref="ParentConsoleSwitch"/> with its process ID; the elevated
/// child, which ShellExecute starts without a usable console, then reattaches
/// to the parent's console (<see cref="AttachToParentConsole"/>) so output
/// appears in the original terminal.
/// </summary>
internal static partial class ElevatedRelaunch
{
    /// <summary>
    /// Internal switch, followed by the parent's process ID, that tells the
    /// elevated child which console to attach to.
    /// </summary>
    public const string ParentConsoleSwitch = "--internal-attach-console=";

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const int StdInputHandle = -10;
    private const int StdOutputHandle = -11;
    private const int StdErrorHandle = -12;
    private static readonly IntPtr InvalidHandleValue = new(-1);

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool TryRelaunch(string[] args, out int exitCode)
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
        psi.ArgumentList.Add($"{ParentConsoleSwitch}{Environment.ProcessId}");
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

    public static void AttachToParentConsole(uint pid)
    {
        FreeConsole();
        if (!AttachConsole(pid))
            AllocConsole();

        IntPtr hin = CreateFileW(
            "CONIN$",
            GenericRead | GenericWrite,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        IntPtr hout = CreateFileW(
            "CONOUT$",
            GenericRead | GenericWrite,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);

        if (hin != InvalidHandleValue)
            SetStdHandle(StdInputHandle, hin);
        if (hout != InvalidHandleValue)
        {
            SetStdHandle(StdOutputHandle, hout);
            SetStdHandle(StdErrorHandle, hout);
        }

        Console.SetIn(new StreamReader(Console.OpenStandardInput()));
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), Console.OutputEncoding) { AutoFlush = true });
        Console.SetError(new StreamWriter(Console.OpenStandardError(), Console.OutputEncoding) { AutoFlush = true });
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AttachConsole(uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeConsole();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllocConsole();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
}
