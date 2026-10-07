using PfnUseDump.Scan;

namespace PfnUseDump.Report;

/// <summary>
/// Turns the per-file-object page counts gathered by
/// <see cref="Superfetch.Classify"/> into named, merged, size-sorted
/// <see cref="FileRow"/>s.
/// </summary>
internal static class FileRows
{
    private static readonly FileRow EmptyRow = new("", 0, 0, 0, 0, false);

    private static FileRow Sum(FileRow a, FileRow b) => a with
    {
        Active = a.Active + b.Active,
        Standby = a.Standby + b.Standby,
        Modified = a.Modified + b.Modified,
        Total = a.Total + b.Total,
    };

    /// <summary>
    /// Totals for one use type of a key's counts array
    /// (half 0 = Mapped File, half 1 = Metafile; see Superfetch.Classify).
    /// </summary>
    private static FileRow Half(ulong[] c, int half)
    {
        const int standby = 2, modified = 3, modifiedNoWrite = 4, active = 6;
        int n = Superfetch.ListNames.Length;
        int o = half * n;
        ulong total = 0;
        for (int i = 0; i < n; i++)
            total += c[o + i];
        return EmptyRow with
        {
            Active = c[o + active],
            Standby = c[o + standby],
            Modified = c[o + modified] + c[o + modifiedNoWrite],
            Total = total,
        };
    }

    public static List<FileRow> Build(
        Dictionary<ulong, ulong[]> counts, Dictionary<ulong, string> names, bool splitUnresolved)
    {
        var rows = new List<FileRow>(counts.Count);

        // Unresolved tallies per use type: [0] = Mapped File, [1] = Metafile.
        string[] useLabel = ["Mapped File", "Metafile"];
        FileRow[] unresolved = [EmptyRow, EmptyRow];
        int[] unresolvedObjects = [0, 0];

        foreach (var (key, c) in counts)
        {
            FileRow mapped = Half(c, 0);
            FileRow meta = Half(c, 1);
            if (key != 0 && names.TryGetValue(key, out var name))
            {
                rows.Add(Sum(mapped, meta) with { Name = name, Resolved = true });
                continue;
            }

            FileRow[] halves = [mapped, meta];
            for (int h = 0; h < 2; h++)
            {
                if (halves[h].Total == 0)
                    continue;
                unresolved[h] = Sum(unresolved[h], halves[h]);
                unresolvedObjects[h]++;
            }
        }

        // The same file can appear under several keys (e.g. data vs. image
        // section); merge by name so each file is listed once.
        var merged = new Dictionary<string, FileRow>(rows.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
            merged[r.Name] = merged.TryGetValue(r.Name, out var m) ? Sum(m, r) : r;
        rows = [.. merged.Values];

        if (splitUnresolved)
        {
            for (int h = 0; h < 2; h++)
            {
                if (unresolved[h].Total != 0)
                {
                    rows.Add(unresolved[h] with
                    {
                        Name = $"<{English.Plural(unresolvedObjects[h], $"unresolved {useLabel[h]} object")}>",
                    });
                }
            }
        }
        else
        {
            FileRow all = Sum(unresolved[0], unresolved[1]);
            if (all.Total != 0)
            {
                // Metafile pages here are file-system metadata streams (NTFS,
                // ReFS, ...) that the kernel rundown reports without a name -
                // expected. Mapped File pages are genuine misses (typically a
                // file closed between the page scan and the rundown). Say which
                // is which without spending a second line.
                int meta = unresolvedObjects[1];
                int file = unresolvedObjects[0];
                string label = (meta, file) switch
                {
                    (_, 0) => $"<{English.Plural(meta, "unnamed file-system metadata stream")}>",
                    (0, _) => $"<{English.Plural(file, "unresolved file object")}>",
                    _ => $"<{English.Plural(meta, "unnamed metadata stream")} + {English.Plural(file, "unresolved file")}>",
                };
                rows.Add(all with { Name = label });
            }
        }

        rows.Sort((a, b) => b.Total.CompareTo(a.Total));
        return rows;
    }
}
