using PfnUseDump.Terminal;

namespace PfnUseDump.Report;

/// <summary>
/// The "Files in memory" table: per-file Active / Standby / Modified GiB,
/// fitted to the console window unless --all (or --most) is given.
/// </summary>
internal static class FileTable
{
    // --most omits files that would print as 0.000 GiB. 0.0005 GiB is 131.072
    // pages, so the cut-off is 132 pages (~528 KiB): 131 pages displays as
    // 0.000, 132 pages as 0.001.
    private const double MostThresholdGiB = 0.0005;
    private static readonly ulong MostMinPages = (ulong)Math.Ceiling(MostThresholdGiB * Pages.PerGiB);

    /// <param name="rows">All file rows, sorted largest first.</param>
    /// <param name="lineCounter">
    /// Non-null when the table must fit the visible window: rows already
    /// printed this run. Null with --all / --most or redirected output.
    /// </param>
    /// <param name="most">Omit rows that would print as 0.000 GiB.</param>
    /// <param name="debug">Precede the table with the files-in-memory summary line.</param>
    public static void Print(List<FileRow> rows, LineCounter? lineCounter, bool most, bool debug)
    {
        // Rows are sorted largest first, so --most keeps a prefix of the list.
        int eligible = rows.Count;
        if (most)
        {
            eligible = rows.FindIndex(r => r.Total < MostMinPages);
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
            //   2  summary line + blank line (--debug only)
            //   2  column header, rule
            //   2  shell's blank line + next prompt
            // Rows that don't fit are dropped silently; --all lists them. No
            // footer is needed here: --most implies --all, so it never reaches
            // this branch.
            int left = s.Rows - 1 - lineCounter.RowsUsed - (debug ? 2 : 0) - 2 - 2;
            limit = Math.Clamp(left, 0, eligible);
            pathWidth = Math.Max(20, s.Columns - prefixWidth - 1);
        }

        if (debug)
        {
            PrintSummary(rows);
            Console.WriteLine();
        }
        Console.WriteLine($"{"Total GiB",9} {"Active",9} {"Standby",9} {"Modified",9}  File");
        Console.WriteLine(new string('-', 66));
        for (int i = 0; i < limit; i++)
        {
            var r = rows[i];
            Console.WriteLine(
                $"{Pages.ToGiB(r.Total),9:N3} {Pages.ToGiB(r.Active),9:N3} " +
                $"{Pages.ToGiB(r.Standby),9:N3} {Pages.ToGiB(r.Modified),9:N3}  " +
                ClipLeft(r.Name, pathWidth));
        }

        int omitted = rows.Count - eligible;    // below the --most threshold
        if (omitted > 0)
        {
            Console.WriteLine();
            Console.WriteLine(
                $"... {English.Plural(omitted, "file")} under {MostThresholdGiB} GiB " +
                $"({Pages.ToGiB(SumTotal(rows, eligible, rows.Count)):N3} GiB) omitted.");
        }
    }

    /// <summary>
    /// One-line totals for everything in memory (--debug). Always covers all
    /// rows, even with --most.
    /// </summary>
    private static void PrintSummary(List<FileRow> rows)
    {
        ulong total = 0, resolved = 0;
        foreach (var r in rows)
        {
            total += r.Total;
            if (r.Resolved)
                resolved += r.Total;
        }
        int fileCount = rows.Count(r => r.Resolved);
        double pct = total == 0 ? 100 : 100.0 * resolved / total;

        Console.WriteLine(
            $"Files in memory: {fileCount:N0} files, {Pages.ToGiB(total):N3} GiB file-backed " +
            $"({pct:N1}% resolved to a name)");
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

        // Result is root + "..." + tail. The tail starts at a backslash when
        // it can; otherwise it starts mid-name, right after the "...", so a
        // partial folder name doesn't look like a whole one (E:\...ek- The\x).
        ReadOnlySpan<char> tail = s.AsSpan(s.Length - tailLen);
        int sep = tail.IndexOf('\\');
        string tailText = sep >= 0 && tail.Length - sep > tailLen / 2
            ? tail[sep..].ToString()
            : tail.ToString();

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
}
