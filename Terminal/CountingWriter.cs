using System.Text;

namespace PfnUseDump.Terminal;

/// <summary>Pass-through writer that feeds a <see cref="LineCounter"/>.</summary>
internal sealed class CountingWriter(TextWriter inner, LineCounter counter) : TextWriter
{
    public override Encoding Encoding => inner.Encoding;

    public override void Write(char value)
    {
        counter.Count(value);
        inner.Write(value);
    }

    public override void Write(string? value)
    {
        if (value is null)
            return;
        counter.Count(value);
        inner.Write(value);
    }

    public override void Write(char[] buffer, int index, int count)
    {
        counter.Count(buffer.AsSpan(index, count));
        inner.Write(buffer, index, count);
    }

    public override void Write(ReadOnlySpan<char> buffer)
    {
        counter.Count(buffer);
        inner.Write(buffer);
    }

    public override void WriteLine()
    {
        counter.Count('\n');
        inner.WriteLine();
    }

    public override void WriteLine(string? value)
    {
        if (value is not null)
            counter.Count(value);
        counter.Count('\n');
        inner.WriteLine(value);
    }

    public override void Flush() => inner.Flush();
}
