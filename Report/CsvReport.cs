using PfnUseDump.Scan;
using System.Text;

namespace PfnUseDump.Report;

/// <summary>Writes the --csv report: Use and List totals, plus every file.</summary>
internal static class CsvReport
{
    public static void Write(string path, ulong[] use, ulong[] list, ulong[]? standbyByPriority, List<FileRow>? files)
    {
        using var w = new StreamWriter(path, false, new UTF8Encoding(false));
        w.WriteLine("Kind,Name,Pages,Bytes,ActivePages,StandbyPages,ModifiedPages");
        for (int i = 0; i < Superfetch.UseNames.Length; i++)
            w.WriteLine($"Use,{Superfetch.UseNames[i]},{use[i]},{use[i] * Pages.Size},,,");
        for (int i = 0; i < Superfetch.ListNames.Length; i++)
            w.WriteLine($"List,{Superfetch.ListNames[i]},{list[i]},{list[i] * Pages.Size},,,");
        if (standbyByPriority is not null)
        {
            for (int i = 0; i < standbyByPriority.Length; i++)
                w.WriteLine($"StandbyPriority,{i},{standbyByPriority[i]},{standbyByPriority[i] * Pages.Size},,,");
        }
        if (files is not null)
        {
            foreach (var f in files)
            {
                string name = "\"" + f.Name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
                w.WriteLine($"File,{name},{f.Total},{f.Total * Pages.Size},{f.Active},{f.Standby},{f.Modified}");
            }
        }
        Console.Error.WriteLine($"Wrote {path}");
    }
}
