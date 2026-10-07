using System.Runtime.InteropServices;

namespace PfnUseDump.Terminal;

/// <summary>Console window geometry, queried directly from CONOUT$.</summary>
internal static partial class ConsoleWindow
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ConsoleScreenBufferInfo
    {
        public short SizeX, SizeY;
        public short CursorX, CursorY;
        public ushort Attributes;
        public short Left, Top, Right, Bottom;
        public short MaxX, MaxY;
    }

    private const int StdOutputHandle = -11;
    private const uint FileTypeChar = 0x0002;

    /// <summary>
    /// Visible console rows and columns, or null if stdout is not a console
    /// (redirected to a file or pipe), in which case output should not be truncated.
    /// </summary>
    public static (int Rows, int Columns)? VisibleSize()
    {
        IntPtr h = GetStdHandle(StdOutputHandle);
        return h != IntPtr.Zero
            && h != new IntPtr(-1)
            && GetFileType(h) == FileTypeChar
            && GetConsoleScreenBufferInfo(h, out var info)
            ? (info.Bottom - info.Top + 1, info.Right - info.Left + 1)
            : null;
    }

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetStdHandle(int nStdHandle);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetFileType(IntPtr hFile);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleScreenBufferInfo(IntPtr hConsoleOutput, out ConsoleScreenBufferInfo info);
}
