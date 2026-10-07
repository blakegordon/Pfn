namespace PfnUseDump.Report;

/// <summary>Conversions for counts of 4 KiB physical pages.</summary>
internal static class Pages
{
    public const ulong Size = 4096;
    public const ulong PerGiB = 1024UL * 1024 * 1024 / Size;

    public static double ToGiB(ulong pages) => pages / (double)PerGiB;
}
