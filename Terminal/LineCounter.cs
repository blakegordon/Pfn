namespace PfnUseDump.Terminal;

/// <summary>
/// Tracks how many console rows our own output has consumed (stdout and
/// stderr both land on the same console), including soft wraps at the
/// window width, so the file table can be sized to fit what's left.
/// </summary>
internal sealed class LineCounter(int width)
{
    private int _column;

    public int Width { get; } = Math.Max(1, width);

    public int Lines { get; private set; }

    /// <summary>Rows used so far, counting a partially written line.</summary>
    public int RowsUsed => Lines + (_column > 0 ? 1 : 0);

    public void Count(ReadOnlySpan<char> s)
    {
        foreach (char ch in s)
            Count(ch);
    }

    public void Count(char ch)
    {
        switch (ch)
        {
            case '\n':
                Lines++;
                _column = 0;
                break;
            case '\r':
                _column = 0;
                break;
            default:
                if (_column == Width)
                {
                    Lines++;
                    _column = 0;
                }
                _column++;
                break;
        }
    }
}
