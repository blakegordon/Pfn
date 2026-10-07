namespace PfnUseDump.Report;

/// <summary>Small helpers for English wording in report text.</summary>
internal static class English
{
    /// <summary>"1 file", "2 files", "1,234 files".</summary>
    public static string Plural(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n:N0} {noun}s";
}
