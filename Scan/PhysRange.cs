namespace PfnUseDump.Scan;

/// <summary>
/// A run of physical pages. The layout matches the kernel's
/// PF_PHYSICAL_MEMORY_RANGE, so <see cref="Superfetch.QueryRanges"/> reads
/// the reply directly as PhysRange values; keep the two fields in this order.
/// </summary>
internal readonly record struct PhysRange(ulong BasePfn, ulong PageCount);
