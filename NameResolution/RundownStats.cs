namespace PfnUseDump.NameResolution;

/// <summary>Final statistics of the file-rundown ETW session (shown by --debug).</summary>
internal readonly record struct RundownStats(
    uint EventsLost,
    uint BuffersWritten,
    uint LogBuffersLost,
    uint BufferSizeKB,
    uint MaximumBuffers,
    int NamesCollected,
    string Session);
