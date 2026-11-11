using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DocSentinel.UI.Ipc;

/// <summary>
/// Self-contained RFC-compliant MessagePack &lt;-&gt; JsonNode codec with 4-byte LE frame header.
/// Matches Rust `rmp_serde::to_vec_named` / `from_slice` with zero external NuGet dependencies.
/// </summary>
public static class MsgPackCodec
{
    public const int MaxFrameSize = 64 * 1024 * 1024;

    public static async Task WriteFrameAsync(Stream stream, JsonNode node, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        WriteNode(ms, node);
        var payload = ms.ToArray();
        if (payload.Length > MaxFrameSize)
            throw new InvalidOperationException($"Frame size {payload.Length} exceeds {MaxFrameSize}");

        var lenBuf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lenBuf, (uint)payload.Length);
        await stream.WriteAsync(lenBuf, ct);
        await stream.WriteAsync(payload, ct);
        await stream.FlushAsync(ct);
    }

    public static async Task<JsonNode?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactAsync(stream, lenBuf, ct))
            return null;

        int len = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(lenBuf));
        if (len < 0 || len > MaxFrameSize)
            throw new InvalidDataException($"Invalid frame length: {len}");

        var payload = new byte[len];
        if (!await ReadExactAsync(stream, payload, ct))
            throw new EndOfStreamException("Unexpected EOF in frame payload");

        int offset = 0;
        return ReadNode(payload, ref offset);
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buf, CancellationToken ct)
    {
        int readTotal = 0;
        while (readTotal < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(readTotal, buf.Length - readTotal), ct);
            if (n == 0)
            {
                if (readTotal == 0) return false;
                throw new EndOfStreamException("Partial frame read");
            }
            readTotal += n;
        }
        return true;
    }

    public static void WriteNode(Stream s, JsonNode? node)
    {
        if (node is null)
        {
            s.WriteByte(0xc0);
            return;
        }

        switch (node)
        {
            case JsonValue val:
                WriteJsonValue(s, val);
                break;
            case JsonArray arr:
                WriteArrayHeader(s, arr.Count);
                foreach (var item in arr)
                    WriteNode(s, item);
                break;
            case JsonObject obj:
                WriteMapHeader(s, obj.Count);
                foreach (var kv in obj)
                {
                    WriteString(s, kv.Key);
                    WriteNode(s, kv.Value);
                }
                break;
        }
    }

    private static void WriteJsonValue(Stream s, JsonValue val)
    {
        if (!val.TryGetValue<JsonElement>(out var je))
            je = JsonSerializer.SerializeToElement(val);

        switch (je.ValueKind)
        {
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                s.WriteByte(0xc0);
                break;
            case JsonValueKind.True:
                s.WriteByte(0xc3);
                break;
            case JsonValueKind.False:
                s.WriteByte(0xc2);
                break;
            case JsonValueKind.String:
                WriteString(s, je.GetString() ?? string.Empty);
                break;
            case JsonValueKind.Number:
                if (je.TryGetInt64(out long i64))
                    WriteInt64(s, i64);
                else if (je.TryGetUInt64(out ulong u64))
                    WriteUInt64(s, u64);
                else
                    WriteFloat64(s, je.GetDouble());
                break;
            default:
                s.WriteByte(0xc0);
                break;
        }
    }

    private static void WriteInt64(Stream s, long v)
    {
        if (v >= 0)
        {
            WriteUInt64(s, (ulong)v);
            return;
        }
        if (v >= -32)
        {
            s.WriteByte((byte)(sbyte)v);
        }
        else if (v >= sbyte.MinValue)
        {
            s.WriteByte(0xd0);
            s.WriteByte((byte)(sbyte)v);
        }
        else if (v >= short.MinValue)
        {
            s.WriteByte(0xd1);
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteInt16BigEndian(b, (short)v);
            s.Write(b);
        }
        else if (v >= int.MinValue)
        {
            s.WriteByte(0xd2);
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(b, (int)v);
            s.Write(b);
        }
        else
        {
            s.WriteByte(0xd3);
            Span<byte> b = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(b, v);
            s.Write(b);
        }
    }

    private static void WriteUInt64(Stream s, ulong v)
    {
        if (v <= 0x7f)
        {
            s.WriteByte((byte)v);
        }
        else if (v <= byte.MaxValue)
        {
            s.WriteByte(0xcc);
            s.WriteByte((byte)v);
        }
        else if (v <= ushort.MaxValue)
        {
            s.WriteByte(0xcd);
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)v);
            s.Write(b);
        }
        else if (v <= uint.MaxValue)
        {
            s.WriteByte(0xce);
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, (uint)v);
            s.Write(b);
        }
        else
        {
            s.WriteByte(0xcf);
            Span<byte> b = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(b, v);
            s.Write(b);
        }
    }

    private static void WriteFloat64(Stream s, double d)
    {
        s.WriteByte(0xcb);
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteDoubleBigEndian(b, d);
        s.Write(b);
    }

    private static void WriteString(Stream s, string str)
    {
        var bytes = Encoding.UTF8.GetBytes(str);
        int n = bytes.Length;
        if (n <= 31)
        {
            s.WriteByte((byte)(0xa0 | n));
        }
        else if (n <= byte.MaxValue)
        {
            s.WriteByte(0xd9);
            s.WriteByte((byte)n);
        }
        else if (n <= ushort.MaxValue)
        {
            s.WriteByte(0xda);
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)n);
            s.Write(b);
        }
        else
        {
            s.WriteByte(0xdb);
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, (uint)n);
            s.Write(b);
        }
        s.Write(bytes);
    }

    private static void WriteArrayHeader(Stream s, int count)
    {
        if (count <= 15)
        {
            s.WriteByte((byte)(0x90 | count));
        }
        else if (count <= ushort.MaxValue)
        {
            s.WriteByte(0xdc);
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)count);
            s.Write(b);
        }
        else
        {
            s.WriteByte(0xdd);
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, (uint)count);
            s.Write(b);
        }
    }

    private static void WriteMapHeader(Stream s, int count)
    {
        if (count <= 15)
        {
            s.WriteByte((byte)(0x80 | count));
        }
        else if (count <= ushort.MaxValue)
        {
            s.WriteByte(0xde);
            Span<byte> b = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(b, (ushort)count);
            s.Write(b);
        }
        else
        {
            s.WriteByte(0xdf);
            Span<byte> b = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, (uint)count);
            s.Write(b);
        }
    }

    public static JsonNode? ReadNode(ReadOnlySpan<byte> buf, ref int pos)
    {
        byte tag = buf[pos++];
        if (tag <= 0x7f) return JsonValue.Create((int)tag);
        if (tag >= 0xe0) return JsonValue.Create((int)(sbyte)tag);
        if ((tag & 0xf0) == 0x80) return ReadMap(buf, ref pos, tag & 0x0f);
        if ((tag & 0xf0) == 0x90) return ReadArray(buf, ref pos, tag & 0x0f);
        if ((tag & 0xe0) == 0xa0) return ReadStr(buf, ref pos, tag & 0x1f);

        switch (tag)
        {
            case 0xc0: return null;
            case 0xc2: return JsonValue.Create(false);
            case 0xc3: return JsonValue.Create(true);
            case 0xc4: return ReadBin(buf, ref pos, buf[pos++]);
            case 0xc5: return ReadBin(buf, ref pos, ReadU16(buf, ref pos));
            case 0xc6: return ReadBin(buf, ref pos, checked((int)ReadU32(buf, ref pos)));
            case 0xca: return JsonValue.Create(ReadF32(buf, ref pos));
            case 0xcb: return JsonValue.Create(ReadF64(buf, ref pos));
            case 0xcc: return JsonValue.Create((uint)buf[pos++]);
            case 0xcd: return JsonValue.Create((uint)ReadU16(buf, ref pos));
            case 0xce: return JsonValue.Create(ReadU32(buf, ref pos));
            case 0xcf: return JsonValue.Create(ReadU64(buf, ref pos));
            case 0xd0: return JsonValue.Create((int)(sbyte)buf[pos++]);
            case 0xd1: return JsonValue.Create((int)ReadI16(buf, ref pos));
            case 0xd2: return JsonValue.Create(ReadI32(buf, ref pos));
            case 0xd3: return JsonValue.Create(ReadI64(buf, ref pos));
            case 0xd9: return ReadStr(buf, ref pos, buf[pos++]);
            case 0xda: return ReadStr(buf, ref pos, ReadU16(buf, ref pos));
            case 0xdb: return ReadStr(buf, ref pos, checked((int)ReadU32(buf, ref pos)));
            case 0xdc: return ReadArray(buf, ref pos, ReadU16(buf, ref pos));
            case 0xdd: return ReadArray(buf, ref pos, checked((int)ReadU32(buf, ref pos)));
            case 0xde: return ReadMap(buf, ref pos, ReadU16(buf, ref pos));
            case 0xdf: return ReadMap(buf, ref pos, checked((int)ReadU32(buf, ref pos)));
            default:
                throw new InvalidDataException($"Unsupported MessagePack tag 0x{tag:x2}");
        }
    }

    private static JsonArray ReadArray(ReadOnlySpan<byte> buf, ref int pos, int count)
    {
        var arr = new JsonArray();
        for (int i = 0; i < count; i++)
            arr.Add(ReadNode(buf, ref pos));
        return arr;
    }

    private static JsonObject ReadMap(ReadOnlySpan<byte> buf, ref int pos, int count)
    {
        var obj = new JsonObject();
        for (int i = 0; i < count; i++)
        {
            var keyNode = ReadNode(buf, ref pos);
            var valNode = ReadNode(buf, ref pos);
            string key = keyNode?.ToString() ?? string.Empty;
            obj[key] = valNode;
        }
        return obj;
    }

    private static JsonNode ReadStr(ReadOnlySpan<byte> buf, ref int pos, int len)
    {
        var s = Encoding.UTF8.GetString(buf.Slice(pos, len));
        pos += len;
        return JsonValue.Create(s)!;
    }

    private static JsonNode ReadBin(ReadOnlySpan<byte> buf, ref int pos, int len)
    {
        var arr = new JsonArray();
        for (int i = 0; i < len; i++)
            arr.Add(JsonValue.Create((int)buf[pos + i]));
        pos += len;
        return arr;
    }

    private static ushort ReadU16(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadUInt16BigEndian(buf.Slice(pos, 2));
        pos += 2;
        return v;
    }

    private static uint ReadU32(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(pos, 4));
        pos += 4;
        return v;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadUInt64BigEndian(buf.Slice(pos, 8));
        pos += 8;
        return v;
    }

    private static short ReadI16(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadInt16BigEndian(buf.Slice(pos, 2));
        pos += 2;
        return v;
    }

    private static int ReadI32(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadInt32BigEndian(buf.Slice(pos, 4));
        pos += 4;
        return v;
    }

    private static long ReadI64(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadInt64BigEndian(buf.Slice(pos, 8));
        pos += 8;
        return v;
    }

    private static float ReadF32(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadSingleBigEndian(buf.Slice(pos, 4));
        pos += 4;
        return v;
    }

    private static double ReadF64(ReadOnlySpan<byte> buf, ref int pos)
    {
        var v = BinaryPrimitives.ReadDoubleBigEndian(buf.Slice(pos, 8));
        pos += 8;
        return v;
    }
}

public static class JsonNodeExt
{
    public static ulong AsUInt64(this JsonNode? node, ulong fallback = 0)
    {
        if (node is not JsonValue jv) return fallback;
        if (jv.TryGetValue<ulong>(out var u)) return u;
        if (jv.TryGetValue<long>(out var l) && l >= 0) return (ulong)l;
        if (jv.TryGetValue<uint>(out var u32)) return u32;
        if (jv.TryGetValue<int>(out var i32) && i32 >= 0) return (ulong)i32;
        if (jv.TryGetValue<double>(out var d) && d >= 0) return (ulong)d;
        return fallback;
    }

    public static int AsInt32(this JsonNode? node, int fallback = 0)
    {
        if (node is not JsonValue jv) return fallback;
        if (jv.TryGetValue<int>(out var i)) return i;
        if (jv.TryGetValue<long>(out var l)) return (int)Math.Clamp(l, int.MinValue, int.MaxValue);
        if (jv.TryGetValue<uint>(out var u32)) return (int)Math.Min(u32, int.MaxValue);
        if (jv.TryGetValue<ulong>(out var u64)) return (int)Math.Min(u64, int.MaxValue);
        return fallback;
    }

    public static string AsStr(this JsonNode? node, string fallback = "") =>
        node is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : fallback;

    public static bool AsBool(this JsonNode? node, bool fallback = false) =>
        node is JsonValue jv && jv.TryGetValue<bool>(out var b) ? b : fallback;
}
