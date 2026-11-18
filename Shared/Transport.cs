using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BijouShare.Shared;

public sealed class SecureTransport : IDisposable
{
    private readonly Stream stream;
    private readonly AesGcm sender;
    private readonly AesGcm receiver;
    private readonly byte[] sendPrefix;
    private readonly byte[] receivePrefix;
    private ulong sendSequence;
    private ulong receiveSequence;
    private readonly SemaphoreSlim sendGate = new(1, 1);
    private readonly SemaphoreSlim receiveGate = new(1, 1);
    private int disposed;
    public bool BinaryPayloads
    {
        get;
    }
    public string? RemoteUserName
    {
        get; internal set;
    }
    public string? RemoteDeviceName
    {
        get; internal set;
    }
    public byte[]? RemoteIdentityPublicKey
    {
        get; internal set;
    }
    public string? RemoteServerId
    {
        get; internal set;
    }
    public string? RemoteServerName
    {
        get; internal set;
    }
    public byte[]? RemoteServerIdentityPublicKey
    {
        get; internal set;
    }
    public SecureTransport(Stream stream, byte[] material, bool server, bool binaryPayloads = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(material);
        if (material.Length != 72)
            throw new ArgumentException("Expected 72 bytes of session material.", nameof(material));
        this.stream = stream;
        BinaryPayloads = binaryPayloads;
        sender = new AesGcm(material.AsSpan(server ? 32 : 0, 32), 16);
        receiver = new AesGcm(material.AsSpan(server ? 0 : 32, 32), 16);
        sendPrefix = material.AsSpan(server ? 68 : 64, 4).ToArray();
        receivePrefix = material.AsSpan(server ? 64 : 68, 4).ToArray();
    }
    public async Task SendAsync<T>(T message, CancellationToken token)
    {
        await sendGate.WaitAsync(token);
        byte[]? clear = null;
        byte[]? output = null;
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            if (sendSequence == ulong.MaxValue)
                throw new CryptographicException("Session exhausted.");
            var encoded = RpcEncoding.Encode(message, BinaryPayloads);
            clear = encoded.Buffer;
            var clearLength = encoded.Length;
            if (clearLength > Wire.MaxFrame - 16)
                throw new InvalidDataException("Message too large.");
            var frameLength = clearLength + 16;
            output = ArrayPool<byte>.Shared.Rent(frameLength + 4);
            BinaryPrimitives.WriteInt32BigEndian(output, frameLength);
            var nonce = Nonce(sendPrefix, sendSequence++);
            sender.Encrypt(nonce, clear.AsSpan(0, clearLength), output.AsSpan(4, clearLength), output.AsSpan(4 + clearLength, 16), nonce);
            await stream.WriteAsync(output.AsMemory(0, frameLength + 4), token);
        }
        catch { Dispose(); throw; }
        finally
        {
            if (clear is not null)
            {
                if (BinaryPayloads)
                    ArrayPool<byte>.Shared.Return(clear, clearArray: true);
                else
                    CryptographicOperations.ZeroMemory(clear);
            }
            if (output is not null)
                ArrayPool<byte>.Shared.Return(output);
            sendGate.Release();
        }
    }
    public async Task<T> ReceiveAsync<T>(CancellationToken token)
    {
        await receiveGate.WaitAsync(token);
        byte[]? clear = null;
        byte[]? encrypted = null;
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            if (receiveSequence == ulong.MaxValue)
                throw new CryptographicException("Session exhausted.");
            var header = new byte[4];
            await stream.ReadExactlyAsync(header, token);
            var frameLength = BinaryPrimitives.ReadInt32BigEndian(header);
            if (frameLength < 16 || frameLength > Wire.MaxFrame)
                throw new InvalidDataException("Invalid frame.");
            encrypted = ArrayPool<byte>.Shared.Rent(frameLength);
            await stream.ReadExactlyAsync(encrypted.AsMemory(0, frameLength), token);
            var clearLength = frameLength - 16;
            clear = ArrayPool<byte>.Shared.Rent(clearLength);
            var nonce = Nonce(receivePrefix, receiveSequence++);
            receiver.Decrypt(nonce, encrypted.AsSpan(0, clearLength), encrypted.AsSpan(clearLength, 16), clear.AsSpan(0, clearLength), nonce);
            var result = RpcEncoding.Decode<T>(clear, clearLength, BinaryPayloads);
            if (result is RpcRequest { OwnsFrame: true })
                clear = null; // The request releases its authenticated payload after execution.
            return result;
        }
        catch { Dispose(); throw; }
        finally
        {
            if (clear is not null)
                ArrayPool<byte>.Shared.Return(clear, clearArray: true);
            if (encrypted is not null)
                ArrayPool<byte>.Shared.Return(encrypted);
            receiveGate.Release();
        }
    }
    private static byte[] Nonce(byte[] prefix, ulong sequence)
    {
        var nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), sequence);
        return nonce;
    }
    public static async Task WritePlainAsync<T>(Stream stream, T value, CancellationToken token)
    {
        var bytes = Wire.Encode(value);
        if (bytes.Length > 8192)
            throw new InvalidDataException("Handshake message too large.");
        await WriteFrameAsync(stream, bytes, token);
    }
    public static async Task<T> ReadPlainAsync<T>(Stream stream, CancellationToken token) =>
        Wire.Decode<T>(await ReadFrameAsync(stream, 8192, token));
    private static async Task WriteFrameAsync(Stream stream, byte[] bytes, CancellationToken token)
    {
        var length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        await stream.WriteAsync(length, token);
        await stream.WriteAsync(bytes, token);
        await stream.FlushAsync(token);
    }
    private static async Task<byte[]> ReadFrameAsync(Stream stream, int limit, CancellationToken token)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, token);
        var size = BinaryPrimitives.ReadInt32BigEndian(header);
        if (size < 2 || size > limit)
            throw new InvalidDataException("Invalid frame length.");
        var bytes = new byte[size];
        await stream.ReadExactlyAsync(bytes, token);
        return bytes;
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
            return;
        sender.Dispose();
        receiver.Dispose();
        stream.Dispose();
    }
}
