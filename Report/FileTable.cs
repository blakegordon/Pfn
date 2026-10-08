using PfnUseDump.Terminal;

namespace PfnUseDump.Report;

/// <summary>
/// The "Files in memory" table: per-file Total and Standby GiB (Total and
/// Active with --live), fitted to the console window unless --all (or
/// --most) is given. Only two numeric columns, to leave room for long
/// paths: Total - Standby is the file's Active + Modified, so a gap still
/// flags live or dirty pages. The CSV report has all four counts.
/// </summary>
internal static class FileTable
{
    // --most omits files that would print as 0.000 GiB. 0.0005 GiB is 131.072
    // pages, so the cut-off is 132 pages (~528 KiB): 131 pages displays as
    // 0.000, 132 pages as 0.001. --live applies the same cut-off to Active.
    private const double MostThresholdGiB = 0.0005;
    private static readonly ulong MostMinPages = (ulong)Math.Ceiling(MostThresholdGiB * Pages.PerGiB);

    // Fewest files listed when fitting to the window, so a small screen still
    // shows something useful (the output may then scroll).
    private const int MinFittedRows = 5;

    /// <param name="rows">All file rows, sorted largest first.</param>
    /// <param name="lineCounter">
    /// Non-null when the table must fit the visible window: rows already
    /// printed this run. Null with --all / --most or redirected output.
    /// </param>
    /// <param name="most">Omit rows that would print as 0.000 GiB.</param>
    /// <param name="live">
    /// List only rows whose Active column would not print as 0.000, sorted
    /// by Active, largest first.
    /// </param>
    /// <param name="debug">Precede the table with the files-in-memory summary line.</param>
    public static void Print(List<FileRow> rows, LineCounter? lineCounter, bool most, bool live, bool debug)
    {
        // The rows to list, and how to describe the rest in the footer.
        List<FileRow> shown = rows;
        string omittedAs = $"under {MostThresholdGiB} GiB";
        if (live)
        {
            shown = [.. rows.Where(r => r.Active >= MostMinPages).OrderByDescending(r => r.Active)];
            omittedAs = $"with under {MostThresholdGiB} GiB Active";
        }
        else if (most)
        {
            // Rows are sorted largest first, so --most keeps a prefix of the list.
            int keep = rows.FindIndex(r => r.Total < MostMinPages);
            shown = keep < 0 ? rows : rows[..keep];
        }

        // Prefix: two 9-wide columns, a single space between, two before path.
        const int prefixWidth = 9 * 2 + 1 + 2;

        int limit = shown.Count;
        int pathWidth = int.MaxValue;
        if (lineCounter is not null && ConsoleWindow.VisibleSize() is { } s)
        {
            // Everything this run puts on screen must fit in the window:
            //   1  the command line that launched us
            //   N  rows already printed (status lines, category tables)
            //   2  summary line + blank line (--debug only)
            //   2  column header, rule
            //   2  shell's blank line + next prompt
            // Rows that don't fit are dropped silently, and so is the footer;
            // --all lists everything. On a short window, though, at least
            // MinFittedRows files are listed even if the output then scrolls.
            int left = s.Rows - 1 - lineCounter.RowsUsed - (debug ? 2 : 0) - 2 - 2;
            limit = Math.Min(Math.Max(left, MinFittedRows), shown.Count);
            pathWidth = Math.Max(20, s.Columns - prefixWidth - 1);
        }

        if (debug)
        {
            PrintSummary(rows);
            Console.WriteLine();
        }
        // Second column: Standby normally; Active with --live, the list's sort key.
        string secondName = live ? "Active" : "Standby";
        Console.WriteLine($"{"Total GiB",9} {secondName,9}  File");
        Console.WriteLine(new string('-', 46));
        for (int i = 0; i < limit; i++)
        {
            var r = shown[i];
            string total = $"{Pages.ToGiB(r.Total),9:N3}";
            string second = $"{Pages.ToGiB(live ? r.Active : r.Standby),9:N3}";

            // Without --live, '*' marks rows whose Standby differs from Total as
            // printed, i.e. rows with Active or Modified pages, so they stand out
            // without comparing every pair. It uses the first of the two spaces
            // before the path, so the columns stay aligned.
            string mark = !live && second != total ? "*" : " ";
            Console.WriteLine($"{total} {second}{mark} {ClipLeft(r.Name, pathWidth)}");
        }

        int omitted = rows.Count - shown.Count;    // filtered out by --most / --live
        if (omitted > 0 && lineCounter is null)
        {
            ulong omittedPages = SumTotal(rows) - SumTotal(shown);
            Console.WriteLine();
            Console.WriteLine(
                $"... {English.Plural(omitted, "file")} {omittedAs} " +
                $"({Pages.ToGiB(omittedPages):N3} GiB) omitted.");
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

    private static ulong SumTotal(List<FileRow> rows)
    {
        ulong sum = 0;
        foreach (var r in rows)
            sum += r.Total;
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
