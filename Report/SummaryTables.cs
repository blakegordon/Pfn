using PfnUseDump.Scan;

namespace PfnUseDump.Report;

/// <summary>The Use and List summary tables (RAMMap's Use Counts), in GiB.</summary>
internal static class SummaryTables
{
    // Name column (18) + space + GiB column (10).
    private static readonly string Rule = new('-', 18 + 1 + 10);

    public static void PrintUse(ulong[] use, bool top)
    {
        Console.WriteLine($"{"Use",-18} {"GiB",10}");
        Console.WriteLine(Rule);

        var rows = new List<(string Name, ulong Pages, string Suffix)>(Superfetch.UseNames.Length + 1);
        for (int i = 0; i < Superfetch.UseNames.Length; i++)
        {
            string suffix = i == Superfetch.UseDriverLocked ? "  <== guest RAM / locked MDLs" : "";
            rows.Add((Superfetch.UseNames[i], use[i], suffix));
        }

        ulong other = 0;
        for (int i = Superfetch.UseNames.Length; i < use.Length; i++)
            other += use[i];
        if (other != 0)
            rows.Add(("Other", other, ""));

        PrintCategoryRows(rows, top);
    }

    public static void PrintList(ulong[] list, bool top)
    {
        Console.WriteLine($"{"List",-18} {"GiB",10}");
        Console.WriteLine(Rule);

        var rows = new List<(string Name, ulong Pages, string Suffix)>(Superfetch.ListNames.Length);
        for (int i = 0; i < Superfetch.ListNames.Length; i++)
            rows.Add((Superfetch.ListNames[i], list[i], ""));

        PrintCategoryRows(rows, top);
    }

    /// <summary>
    /// Standby pages by priority (--priority). Rows stay in priority order,
    /// even with --top, because that order is what Windows reuses them in.
    /// </summary>
    public static void PrintStandbyPriority(ulong[] standbyByPriority, bool top)
    {
        Console.WriteLine($"{"Standby priority",-18} {"GiB",10}");
        Console.WriteLine(Rule);

        var rows = new List<(string Name, ulong Pages, string Suffix)>(standbyByPriority.Length);
        for (int i = 0; i < standbyByPriority.Length; i++)
        {
            string suffix = i == 0 ? "  <== reused first"
                : i == standbyByPriority.Length - 1 ? "  <== kept longest"
                : "";
            rows.Add(($"{i}", standbyByPriority[i], suffix));
        }

        PrintCategoryRows(rows, top, sortBySize: false);
    }

    private static void PrintCategoryRows(
        List<(string Name, ulong Pages, string Suffix)> rows, bool top, bool sortBySize = true)
    {
        IEnumerable<(string Name, ulong Pages, string Suffix)> output = rows;
        if (top)
        {
            output = rows.Where(r => r.Pages >= Pages.PerGiB);
            if (sortBySize)
                output = output.OrderByDescending(r => r.Pages);
        }

        foreach (var (name, pages, suffix) in output)
            Console.WriteLine($"{name,-18} {Pages.ToGiB(pages),10:N3}{suffix}");
    }
}
