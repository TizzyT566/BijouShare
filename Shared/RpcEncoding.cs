using System.Buffers;
using System.Buffers.Binary;

namespace BijouShare.Shared;

internal static class RpcEncoding
{
    public static (byte[] Buffer, int Length) Encode<T>(T message, bool binary)
    {
        if (!binary)
        {
            // Legacy JSON needs a standalone array; optimized frames can copy the caller's exact slice directly.
            if (message is RpcRequest { Data: not null, BorrowedCount: >= 0 } requestSlice)
                message = (T)(object)(requestSlice with
                {
                    Data = requestSlice.Data.AsSpan(requestSlice.DataOffset, requestSlice.DataCount).ToArray()
                });
            var legacy = Wire.Encode(message);
            return (legacy, legacy.Length);
        }
        byte kind;
        byte[]? data;
        byte[] json;
        int count;
        int offset = 0;
        if (message is RpcRequest request)
        {
            kind = 1;
            data = request.Data;
            count = request.DataCount;
            offset = request.DataOffset;
            json = Wire.Encode(request with
            {
                Data = null
            });
        }
        else if (message is RpcResponse response)
        {
            kind = 2;
            data = response.Data;
            count = response.DataCount;
            json = Wire.Encode(response with
            {
                Data = null
            });
        }
        else
            throw new InvalidDataException("Unsupported binary message type.");
        if (count < 0 || count > Wire.MaxChunk || offset < 0 ||
            (data is null ? count != 0 : offset > data.Length - count))
            throw new InvalidDataException("Invalid payload bounds.");
        var size = checked(9 + json.Length + count);
        if (size > Wire.MaxFrame - 16)
            throw new InvalidDataException("Message too large.");
        var result = ArrayPool<byte>.Shared.Rent(size);
        result[0] = kind;
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(1), json.Length);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(5), data is null ? -1 : count);
        json.CopyTo(result, 9);
        if (data is not null)
            data.AsSpan(offset, count).CopyTo(result.AsSpan(9 + json.Length));
        return (result, size);
    }

    public static T Decode<T>(byte[] buffer, int length, bool binary)
    {
        var bytes = buffer.AsSpan(0, length);
        if (!binary)
            return System.Text.Json.JsonSerializer.Deserialize<T>(bytes, Wire.Json) ?? throw new InvalidDataException("Empty message.");
        if (bytes.Length < 9)
            throw new InvalidDataException("Truncated binary message.");
        var expectedKind = typeof(T) == typeof(RpcRequest) ? 1 : typeof(T) == typeof(RpcResponse) ? 2 : 0;
        var jsonLength = BinaryPrimitives.ReadInt32LittleEndian(bytes[1..]);
        var dataLength = BinaryPrimitives.ReadInt32LittleEndian(bytes[5..]);
        if (bytes[0] != expectedKind || jsonLength < 2 || dataLength < -1 || dataLength > Wire.MaxChunk ||
            jsonLength > bytes.Length - 9 || Math.Max(0, dataLength) != bytes.Length - 9 - jsonLength)
            throw new InvalidDataException("Invalid binary message bounds.");
        var metadata = System.Text.Json.JsonSerializer.Deserialize<T>(bytes.Slice(9, jsonLength), Wire.Json)
            ?? throw new InvalidDataException("Empty message.");
        if (metadata is RpcRequest borrowed && borrowed.Data is null && dataLength >= 0)
            return (T)(object)(borrowed with
            {
                Data = buffer,
                DataOffset = 9 + jsonLength,
                BorrowedCount = dataLength,
                OwnsFrame = true
            });
        var data = dataLength < 0 ? null : bytes[(9 + jsonLength)..].ToArray();
        return metadata switch
        {
            RpcRequest request when request.Data is null => (T)(object)(request with { Data = data }),
            RpcResponse response when response.Data is null => (T)(object)(response with { Data = data }),
            _ => throw new InvalidDataException("Inline file data is not allowed in binary metadata.")
        };
    }
}
