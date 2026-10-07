namespace PfnUseDump.Report;

/// <summary>
/// Pages one file (or one group of unresolved file objects) has in memory,
/// by list. <see cref="Resolved"/> is false for the unresolved group.
/// </summary>
internal sealed record FileRow(string Name, ulong Active, ulong Standby, ulong Modified, ulong Total, bool Resolved);
