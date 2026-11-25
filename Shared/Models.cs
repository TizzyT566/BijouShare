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
    public const int Version = 6;
    public const string ProtocolName = "BijouShare-v6";
    public const string CryptoSuite = "P256-MLKEM768-SHA3-256-AES256GCM";
    public const int MaxHandshakeFrame = 16 * 1024;
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

public sealed record EnrollmentRequest(string DeviceId, string DeviceName, string ClientPublicKey, string ClientMlKemPublicKey);
public sealed record ClientHello(int Version, string DeviceId, byte[] Nonce, byte[] EphemeralPublicKey)
{
    public string? CryptoSuite { get; init; }
    public byte[]? MlKemPublicKey { get; init; }
    public byte[]? IdentityMlKemPublicKey { get; init; }
    public string? ClientPublicKey { get; init; }
    public string? DeviceName { get; init; }
    public bool InviteEnrollment { get; init; }
    public bool BinaryPayloads { get; init; }
}

public sealed record ServerHello(byte[] Nonce, byte[] EphemeralPublicKey)
{
    public int Version { get; init; }
    public string? CryptoSuite { get; init; }
    public string? ServerId { get; init; }
    public string? ServerName { get; init; }
    public byte[]? GlobalIdentityPublicKey { get; init; }
    public byte[]? ServerMlKemPublicKey { get; init; }
    public byte[]? MlKemCiphertext { get; init; }
    public byte[]? IdentityMlKemCiphertext { get; init; }
    public bool InviteEnrollment { get; init; }
    public bool PendingApproval { get; init; }
}

public sealed record ClientKeyExchange(byte[] MlKemCiphertext);
public sealed record ServerProof(byte[] Proof);
public sealed record ClientProof(byte[] Proof);

[Flags]
public enum NetworkServiceProtocol { Tcp = 1, Udp = 2, Both = Tcp | Udp }
[Flags]
public enum NetworkServiceAccess { None = 0, Send = 1, Receive = 2, Both = Send | Receive }
public sealed record NetworkServiceDescriptor(Guid Id, string Name, NetworkServiceProtocol Protocol, int Port, NetworkServiceAccess Access);
public sealed record RelayFrame(byte[] Data, bool End = false)
{
    public const int MaxStreamPayload = 65536;
    public const int MaxDatagramPayload = 65507;
}

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
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public long OutcomeId { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool RecoveryAttempt { get; init; }
    [JsonIgnore]
    public bool TracksOutcome => Operation is "Open" or "Write" or "Flush" or "Resize" or "Allocate" or "Attributes"
        or "Times" or "Move" or "Lock" or "Unlock" or "Cleanup" or "Close";
    public string Operation { get; init; } = "Ping";
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public NetworkServiceProtocol NetworkProtocol { get; init; }
    // Optional directory filter. Older servers ignore it and use their default page size.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SearchPattern { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool BasicDirectoryInfo { get; init; }
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
        if (SearchPattern is not null && (Operation != "List" || SearchPattern.Length > 255))
            throw new ArgumentException("Invalid directory search pattern.");
        if (InviteCode is not null)
            throw new ArgumentException("Enrollment is valid only during connection setup.");
        if (Operation is not ("Ping" or "Space" or "Open" or "Stat" or "List" or "Read" or "Write" or "Flush" or
            "Resize" or "Allocate" or "Attributes" or "Times" or "CanDelete" or "Move" or "Lock" or "Unlock" or
            "Security" or "Cleanup" or "Close" or "GetOutcome" or "AbandonOpen" or "ListNetworkServices"))
            throw new RemoteException("Unsupported");
        if (NetworkProtocol != 0 || Operation == "ListNetworkServices" &&
            (Handle != Guid.Empty || Data is not null || Destination != null || Path != "\\" || Count != 0 || Offset != 0 || Length != 0))
            throw new ArgumentException("Invalid network service request.");
        var receiptControl = Operation is "GetOutcome" or "AbandonOpen";
        if (OutcomeId < 0 || receiptControl && (OutcomeId == 0 || Data is not null || Handle != Guid.Empty) ||
            OutcomeId != 0 && !receiptControl && !TracksOutcome ||
            RecoveryAttempt && (OutcomeId == 0 || !TracksOutcome))
            throw new ArgumentException("Invalid operation receipt.");
        if (Path is null || Path.Length > 2048 || Destination?.Length > 2048 || DataCount > Wire.MaxChunk || Count is < 0 or > Wire.MaxChunk)
            throw new ArgumentException("Invalid request size.");
    }
}

public sealed record RemoteEntry(string Name, FileAttributes Attributes, long Length,
    DateTime CreationTime, DateTime LastAccessTime, DateTime LastWriteTime, Permission Permissions)
{
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;
}

// Explorer needs these WIN32_FIND_DATA fields. The primary timestamp is UTC ticks;
// omitted creation/access times mean they equal the last-write time.
public readonly record struct DirectoryItem(
    [property: JsonPropertyName("n")] string Name,
    [property: JsonPropertyName("a")] int Attributes,
    [property: JsonPropertyName("m")] long Modified,
    [property: JsonPropertyName("s"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] long Size = 0,
    [property: JsonPropertyName("c"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Created = null,
    [property: JsonPropertyName("r"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Accessed = null)
{
    public static DirectoryItem FromEntry(RemoteEntry entry) => new(entry.Name, (int)entry.Attributes, entry.LastWriteTime.Ticks,
        entry.Length, entry.CreationTime == entry.LastWriteTime ? null : entry.CreationTime.Ticks,
        entry.LastAccessTime == entry.LastWriteTime ? null : entry.LastAccessTime.Ticks);
}

public sealed record RpcResponse
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool SupportsNetworkServices { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public NetworkServiceDescriptor[]? NetworkServices { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public NetworkServiceAccess NetworkAccess { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool SupportsSessionResume { get; init; }
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
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<DirectoryItem>? Items { get; init; }
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
