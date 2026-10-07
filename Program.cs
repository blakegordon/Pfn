using PfnUseDump.NameResolution;
using PfnUseDump.Report;
using PfnUseDump.Scan;
using PfnUseDump.Terminal;
using System.ComponentModel;
using System.Security;

namespace PfnUseDump;

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
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            var opt = Options.Parse(args);

            if (opt.AttachPid != 0)
                ElevatedRelaunch.AttachToParentConsole(opt.AttachPid);

            if (opt.Help)
            {
                Console.WriteLine(Options.HelpText);
                return 0;
            }

            if (!Environment.Is64BitProcess)
                throw new PlatformNotSupportedException("64-bit only.");

            if (!ElevatedRelaunch.IsElevated())
            {
                // The elevated copy can't inherit our handles; it would write
                // to the console and leave the redirect target empty.
                if (Console.IsOutputRedirected)
                {
                    Console.Error.WriteLine(
                        "Administrator elevation is required, and output redirection " +
                        "does not carry over to the elevated copy. Run from an elevated prompt.");
                    return 1;
                }
                if (!ElevatedRelaunch.TryRelaunch(args, out int elevatedCode))
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
            if (opt.Files && !opt.All && ConsoleWindow.VisibleSize() is { } win)
            {
                lineCounter = new LineCounter(win.Columns);
                Console.SetOut(new CountingWriter(Console.Out, lineCounter));
                Console.SetError(new CountingWriter(Console.Error, lineCounter));
            }

            PhysRange[] ranges = Superfetch.QueryRanges();

            var use = new ulong[16];
            var list = new ulong[8];
            var fileCounts = opt.Files ? new Dictionary<ulong, ulong[]>() : null;
            DateTime last = DateTime.MinValue;
            Superfetch.Classify(ranges, use, list, fileCounts, (done, total) =>
            {
                if (opt.Quiet)
                    return;
                var now = DateTime.UtcNow;
                if ((now - last).TotalSeconds < 1 && done != total)
                    return;
                last = now;
                double pct = total == 0 ? 100 : 100.0 * done / total;
                // One status line, rewritten in place; the percentage only
                // ever grows longer, so no padding is needed to erase it.
                Console.Error.Write(
                    $"\rScanning {total:N0} pages ({Pages.ToGiB(total):N2} GiB) in " +
                    $"{English.Plural(ranges.Length, "range")}... {pct:N1}%");
            });
            if (!opt.Quiet)
                Console.Error.WriteLine();

            List<FileRow>? fileRows = null;
            RundownStats etwStats = default;
            if (fileCounts is not null)
            {
                if (!opt.Quiet)
                    Console.Error.WriteLine("Resolving file names (kernel ETW file rundown)...");
                var names = FileNames.Collect(out etwStats);
                fileRows = FileRows.Build(fileCounts, names, splitUnresolved: opt.Debug);
            }

            // Blank line between the status lines (stderr) and the report (stdout).
            if (!opt.Quiet)
                Console.Error.WriteLine();

            SummaryTables.PrintUse(use, opt.Top);
            Console.WriteLine();
            SummaryTables.PrintList(list, opt.Top);

            if (fileRows is not null)
            {
                Console.WriteLine();
                if (opt.Debug)
                {
                    // Printed before the file table so the line counter budgets for it.
                    Console.WriteLine(
                        $"[debug] ETW {etwStats.Session}: {etwStats.NamesCollected:N0} names, " +
                        $"events lost {etwStats.EventsLost:N0}, log buffers lost {etwStats.LogBuffersLost:N0}, " +
                        $"{etwStats.BuffersWritten:N0} buffers written " +
                        $"({etwStats.BufferSizeKB:N0} KB, max {etwStats.MaximumBuffers:N0})");
                }
                FileTable.Print(fileRows, lineCounter, opt.Most, opt.Debug);
            }

            if (opt.Csv is not null)
                CsvReport.Write(opt.Csv, use, list, fileRows);

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
            return 2;
        }
    }
}
