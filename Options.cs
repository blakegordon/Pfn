using PfnUseDump.Terminal;

namespace PfnUseDump;

/// <summary>Command-line switches, parsed and with implied switches applied.</summary>
internal sealed class Options
{
    public const string HelpText = """
    Pfn — physical page use counts (RAMMap Use Counts, CLI)

    Usage:
      Pfn [--csv=<file>] [--quiet] [--top] [--priority]
          [--files [--all] [--most] [--live] [--debug]]

    Walks every physical page via Superfetch (same source RAMMap
    uses). Needs elevation; an unelevated launch prompts UAC.
    On a large machine this takes a while.

    --csv=<file>
                Also write the Use and List counts, and with
                --files every file, to <file> as CSV.

    -q, --quiet Show no status lines (scan progress, name
                resolution); print only the report.

    -t, --top   Omit categories under 1 GiB and sort each
                section by size, largest first.

    -p, --priority
                Also show Standby memory by page priority
                (0-7). When memory runs short, Windows reuses
                Standby pages lowest priority first.

    -f, --files List files with pages in RAM (Total and
                Standby GiB), largest first, like RAMMap's File
                Summary. Total - Standby is Active + Modified;
                '*' marks a Standby that differs from Total.
                --csv has all four counts. Names come from a
                short kernel ETW file rundown. The list is cut
                to fit the visible console window unless --all
                is given or output is redirected.

    -a, --all   With --files: list every file (implies --files).

    -m, --most  Like --all, but omit files that would print as
                0.000 GiB (under 0.0005 GiB in memory), i.e.
                the long tail of tiny files (implies --all and
                --files). --csv still covers all files.

    -l, --live  With --files: list only files with Active pages
                (in use right now, not just cached), showing
                Total and Active GiB, largest Active first; omit
                files whose Active would print as 0.000 GiB
                (implies --files).

    -d, --debug With --files: show a files-in-memory summary
                line, ETW session statistics (events / buffers
                lost), and split unresolved file objects by
                use type (implies --files).

    Driver Locked is the row that holds VirtualBox guest RAM when
    the VM is using native VT-x (HM), not process private commit.
    """;

    public bool Help { get; private set; }

    public string? Csv { get; private set; }

    public bool Quiet { get; private set; }

    public bool Top { get; private set; }

    public bool Files { get; private set; }

    public bool All { get; private set; }

    public bool Debug { get; private set; }

    public bool Most { get; private set; }

    public bool Live { get; private set; }

    public bool Priority { get; private set; }

    /// <summary>
    /// Nonzero in the elevated child: the process ID of the unelevated parent
    /// whose console to attach to (see <see cref="ElevatedRelaunch"/>).
    /// </summary>
    public uint AttachPid { get; private set; }

    public static Options Parse(IEnumerable<string> args)
    {
        var o = new Options();
        foreach (var a in args)
        {
            const string attachPrefix = ElevatedRelaunch.ParentConsoleSwitch;
            if (a.StartsWith(attachPrefix, StringComparison.Ordinal))
            {
                if (!uint.TryParse(a.AsSpan(attachPrefix.Length), out uint attachPid))
                    throw new ArgumentException($"Invalid switch: {a}");
                o.AttachPid = attachPid;
                continue;
            }
            if (a is "-h" or "--help" or "/?")
                o.Help = true;
            else if (a is "-q" or "--quiet")
                o.Quiet = true;
            else if (a is "-t" or "--top")
                o.Top = true;
            else if (a is "-f" or "--files")
                o.Files = true;
            else if (a is "-a" or "--all")
                o.All = true;
            else if (a is "-d" or "--debug")
                o.Debug = true;
            else if (a is "-m" or "--most")
                o.Most = true;
            else if (a is "-l" or "--live")
                o.Live = true;
            else if (a is "-p" or "--priority")
                o.Priority = true;
            else if (a.StartsWith("--csv=", StringComparison.OrdinalIgnoreCase))
                o.Csv = a[6..];
            else if (a == "--csv")
                throw new ArgumentException("Use --csv=<file>");
            else
                throw new ArgumentException($"Unknown switch: {a}");
        }

        if (o.Most)
            o.All = true;
        if (o.All || o.Debug || o.Live)
            o.Files = true;

        return o;
    }
}
