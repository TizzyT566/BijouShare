using System.Text.Json;
using System.Text.Json.Serialization;

namespace BijouShare.Shared;

[Flags]
public enum Permission
{
    None = 0,
    ListDirectory = 1,
    ReadData = 2,
    WriteData = 4,
    CreateFiles = 8,
    CreateDirectories = 16,
    Delete = 32,
    Rename = 64,
    ReadAttributes = 128,
    WriteAttributes = 256,
    ReadPermissions = 512,
    FullControl = 1023
}

public static class Wire
{
    public const int Version = 3;
    public const string ProtocolName = "BijouShare-v3";
    public const string CryptoSuite = "P256-MLKEM768-HKDFSHA256-AES256GCM";
    public const int LegacyMaxChunk = 256 * 1024;
    public const int MaxChunk = 1024 * 1024;
    public const int MaxFrame = 2 * 1024 * 1024;
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        MaxDepth = 32,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        Converters = { new JsonStringEnumConverter() }
    };
    public static T Decode<T>(byte[] data) => JsonSerializer.Deserialize<T>(data, Json)
        ?? throw new InvalidDataException("Empty message.");
    public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
}

public sealed record EnrollmentRequest(string DeviceId, string DeviceName, string ClientPublicKey);
public sealed record EnrollmentBundle(string DeviceId, string UserName, string Host, int Port, string ServerPublicKey);
public sealed record ClientHello(int Version, string DeviceId, byte[] Nonce, byte[] EphemeralPublicKey)
{
    public string? CryptoSuite
    {
        get; init;
    }
    public byte[]? MlKemPublicKey
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool InviteEnrollment
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool ServerIdentityMetadata
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DeviceName
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientPublicKey
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BinaryPayloads
    {
        get; init;
    }
}
public sealed record ServerHello(byte[] Nonce, byte[] EphemeralPublicKey, byte[] Proof)
{
    public int Version
    {
        get; init;
    }
    public string? CryptoSuite
    {
        get; init;
    }
    public byte[]? MlKemCiphertext
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool InviteEnrollment
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServerId
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServerName
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? GlobalIdentityPublicKey
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? ServerIdentityProof
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte[]? IdentityPublicKey
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool PendingApproval
    {
        get; init;
    }
}
public sealed record ClientProof(byte[] Proof);

// The server derives group permissions from the authenticated device. RPCs cannot select an identity.
public sealed record RpcRequest
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? InviteCode
    {
        get; init;
    }
    [JsonIgnore]
    internal bool BorrowReadBuffer
    {
        get; init;
    }
    [JsonIgnore]
    internal int DataOffset
    {
        get; init;
    }
    [JsonIgnore] internal int BorrowedCount { get; init; } = -1;
    [JsonIgnore]
    internal bool OwnsFrame
    {
        get; init;
    }
    [JsonIgnore] internal int DataCount => BorrowedCount >= 0 ? BorrowedCount : Data?.Length ?? 0;
    internal void ReleasePayload()
    {
        if (OwnsFrame && Data is not null)
            System.Buffers.ArrayPool<byte>.Shared.Return(Data, clearArray: true);
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public long RequestId
    {
        get; init;
    }
    public string Operation { get; init; } = "Ping";
    public string Path { get; init; } = "\\";
    public string? Destination
    {
        get; init;
    }
    public Guid Handle
    {
        get; init;
    }
    public uint Access
    {
        get; init;
    }
    public FileShare Share
    {
        get; init;
    }
    public FileMode Mode { get; init; } = FileMode.Open;
    public FileAttributes Attributes
    {
        get; init;
    }
    public bool Directory
    {
        get; init;
    }
    public bool Replace
    {
        get; init;
    }
    public bool DeleteOnClose
    {
        get; init;
    }
    public bool Append
    {
        get; init;
    }
    public bool WriteThrough
    {
        get; init;
    }
    public bool PagingIo
    {
        get; init;
    }
    public long Offset
    {
        get; init;
    }
    public long Length
    {
        get; init;
    }
    public int Count
    {
        get; init;
    }
    public byte[]? Data
    {
        get; init;
    }
    public DateTime? CreationTime
    {
        get; init;
    }
    public DateTime? LastAccessTime
    {
        get; init;
    }
    public DateTime? LastWriteTime
    {
        get; init;
    }

    public void Validate()
    {
        if (InviteCode is not null)
            throw new ArgumentException("Enrollment is valid only during connection setup.");
        if (Operation is not ("Ping" or "Space" or "Open" or "Stat" or "List" or "Read" or "Write" or "Flush" or
            "Resize" or "Allocate" or "Attributes" or "Times" or "CanDelete" or "Move" or "Lock" or "Unlock" or
            "Security" or "Cleanup" or "Close"))
            throw new RemoteException("Unsupported");
        if (Path is null || Path.Length > 2048 || Destination?.Length > 2048 || DataCount > Wire.MaxChunk || Count is < 0 or > Wire.MaxChunk)
            throw new ArgumentException("Invalid request size.");
    }
}

public sealed record RemoteEntry(string Name, FileAttributes Attributes, long Length,
    DateTime CreationTime, DateTime LastAccessTime, DateTime LastWriteTime, Permission Permissions)
{
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;
}

public sealed record RpcResponse
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EnrollmentServerPublicKey
    {
        get; init;
    }
    [JsonIgnore] internal int BorrowedCount { get; init; } = -1;
    [JsonIgnore]
    internal bool OwnsData
    {
        get; init;
    }
    [JsonIgnore] internal int DataCount => BorrowedCount >= 0 ? BorrowedCount : Data?.Length ?? 0;
    internal void ReleasePayload()
    {
        if (OwnsData && Data is not null)
            System.Buffers.ArrayPool<byte>.Shared.Return(Data, clearArray: true);
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public long RequestId
    {
        get; init;
    }
    public string? Error
    {
        get; init;
    }
    public string? UserName
    {
        get; init;
    }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DeviceName
    {
        get; init;
    }
    public Guid Handle
    {
        get; init;
    }
    public bool Existed
    {
        get; init;
    }
    public bool More
    {
        get; init;
    }
    public RemoteEntry? Entry
    {
        get; init;
    }
    public List<RemoteEntry>? Entries
    {
        get; init;
    }
    public byte[]? Data
    {
        get; init;
    }
    public long Length
    {
        get; init;
    }
    public long FreeBytes
    {
        get; init;
    }
    public long TotalBytes
    {
        get; init;
    }
    public Permission Permissions
    {
        get; init;
    }
    public static RpcResponse Fail(string code) => new() { Error = code };
}

public sealed class RemoteException(string code) : IOException(code)
{
    public string Code { get; } = code;
}

// Windows FILE_ACCESS_MASK values, independent of the client-side Dokan package.
public static class AccessMask
{
    public const uint ReadData = 0x1, WriteData = 0x2, AppendData = 0x4;
    public const uint ReadEa = 0x8, WriteEa = 0x10, Execute = 0x20;
    public const uint DeleteChild = 0x40, ReadAttributes = 0x80, WriteAttributes = 0x100;
    public const uint Delete = 0x10000, ReadControl = 0x20000;
    public const uint WriteDac = 0x40000, WriteOwner = 0x80000;
    public const uint GenericAll = 0x10000000, GenericExecute = 0x20000000;
    public const uint GenericWrite = 0x40000000, GenericRead = 0x80000000;
    public static bool Reads(uint a) => (a & (ReadData | GenericRead | GenericAll | Execute | GenericExecute)) != 0;
    public static bool Writes(uint a) => (a & (WriteData | AppendData | GenericWrite | GenericAll)) != 0;
    public static bool Deletes(uint a) => (a & (Delete | GenericAll)) != 0;
    public static bool AppendOnly(uint a) => (a & AppendData) != 0 && (a & (WriteData | GenericWrite | GenericAll)) == 0;
}
