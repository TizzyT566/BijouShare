using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using BijouShare.Shared;

namespace BijouShare.Client;

// Persistent Windows Filtering Platform rules protect the interval between a service
// crash and the last user-mode listener closing. Only the elevated broker edits them.
internal static class NetworkPortFilters
{
    private static readonly Guid SublayerKey = new("635cbcf6-904a-4899-a813-fdecc7588eb6");
    private static readonly Guid ConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid ConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid ReceiveV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    private static readonly Guid ReceiveV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    private static readonly Guid RemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid RemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    private static readonly Guid IpProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    private static readonly Guid AleUser = new("af043a0a-b34d-4f86-979c-c90371af6e66");
    private const uint AlreadyExists = 0x80320009, FilterNotFound = 0x80320003,
        InUse = 0x8032000a, SublayerNotFound = 0x80320007;
    private const uint UInt8 = 1, UInt16 = 2, UInt32 = 3, ByteArray16 = 11, SecurityDescriptor = 14;
    private const uint Block = 0x1001, Permit = 0x1002, Persistent = 1;

    internal static IDisposable Protect(int port, NetworkServiceProtocol protocol, SecurityIdentifier owner, int workerPid)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(workerPid);
        if (protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp or NetworkServiceProtocol.Both))
            throw new ArgumentException("Invalid network service protocol.", nameof(protocol));
        using var worker = Process.GetProcessById(workerPid);
        var started = worker.StartTime.ToFileTimeUtc();
        var keys = new List<Guid>();
        Transact((engine, memory) =>
        {
            var display = new Display { Name = memory.String("BijouShare private network services") };
            // Providerless persistent filters also load after a Base Filtering Engine restart on
            // a portable client where there is no auto-start BijouShare service to activate them.
            var sublayer = new Sublayer { Key = SublayerKey, Display = display, Flags = (ushort)Persistent, Weight = ushort.MaxValue };
            Check(FwpmSubLayerAdd0(engine, ref sublayer, 0), AlreadyExists);
            var ownerSid = new byte[owner.BinaryLength];
            owner.GetBinaryForm(ownerSid, 0);
            // ALE_USER_ID matches a token granted FWP_ACTRL_MATCH_FILTER by this descriptor.
            var acl = new RawSecurityDescriptor($"D:(A;;0x1;;;{owner.Value})");
            var descriptor = new byte[acl.BinaryLength];
            acl.GetBinaryForm(descriptor, 0);
            var aclCondition = new Condition(AleUser, SecurityDescriptor, memory.Put(memory.Blob(descriptor)));

            foreach (var existing in ReadRules(engine).Where(row => row.Port == port && (protocol & row.Protocol) != 0))
            {
                if (WorkerAlive(existing.Pid, existing.Started) &&
                    (existing.Pid != workerPid || existing.Started != started || !ownerSid.AsSpan().SequenceEqual(existing.Owner)))
                    throw new IOException("The port is protected for another running BijouShare worker.");
                Delete(engine, existing.Key);
            }
            foreach (var kind in new[] { NetworkServiceProtocol.Tcp, NetworkServiceProtocol.Udp })
            {
                if ((protocol & kind) == 0) continue;
                // ALE permit/block filters require a zero raw context. Keep our lease metadata
                // in the opaque data blob so the broker can recover it after a restart.
                var metadata = new byte[16 + ownerSid.Length];
                BinaryPrimitives.WriteInt32LittleEndian(metadata, workerPid);
                BinaryPrimitives.WriteUInt16LittleEndian(metadata.AsSpan(4), (ushort)port);
                metadata[6] = (byte)kind;
                metadata[7] = 1;
                BinaryPrimitives.WriteInt64LittleEndian(metadata.AsSpan(8), started);
                ownerSid.CopyTo(metadata, 16);
                var ownerData = memory.Blob(metadata);
                var layers = kind == NetworkServiceProtocol.Tcp ? new[] { ConnectV4, ConnectV6 } : new[] { ConnectV4, ConnectV6, ReceiveV4, ReceiveV6 };
                foreach (var layer in layers)
                {
                    bool ipv6 = layer == ConnectV6 || layer == ReceiveV6;
                    var address = ipv6 ? new Condition(RemoteAddress, ByteArray16, memory.Bytes(IPAddress.Loopback.MapToIPv6().GetAddressBytes()))
                        : new Condition(RemoteAddress, UInt32, 0x7f000001);
                    var conditions = new[] { address, new Condition(RemotePort, UInt16, port),
                        new Condition(IpProtocol, UInt8, kind == NetworkServiceProtocol.Tcp ? 6 : 17), aclCondition };
                    var filter = new Filter { Display = display, Flags = Persistent, ProviderData = ownerData,
                        Layer = layer, Sublayer = SublayerKey, Conditions = memory.Array(conditions) };
                    // The more specific permit takes precedence inside our sublayer. Other Windows firewall
                    // policies can still deny the owner. A missing or unmatched user identity hits the block.
                    foreach (bool allow in new[] { false, true })
                    {
                        filter.Key = Guid.NewGuid();
                        filter.Weight = new Value(UInt8, allow ? 15 : 1);
                        filter.Action = new ActionType { Type = allow ? Permit : Block };
                        filter.ConditionCount = allow ? 4u : 3u;
                        Check(FwpmFilterAdd0(engine, ref filter, 0, out _));
                        keys.Add(filter.Key);
                    }
                }
            }
        });
        return new Lease(keys);
    }

    internal static void ReleaseOwned(int port, NetworkServiceProtocol protocol, Process worker, SecurityIdentifier owner) => Transact((engine, _) =>
    {
        var started = worker.StartTime.ToFileTimeUtc();
        foreach (var row in ReadRules(engine))
            if (row.Port == port && (row.Protocol & protocol) != 0 && row.Pid == worker.Id && row.Started == started &&
                owner.Equals(new SecurityIdentifier(row.Owner, 0)))
                Delete(engine, row.Key);
        RemoveEmptySublayer(engine);
    });

    internal static void Sweep(Func<int, NetworkServiceProtocol, bool> portIsFree) => Transact((engine, _) =>
    {
        foreach (var group in ReadRules(engine).GroupBy(row => (row.Port, row.Protocol, row.Pid, row.Started)))
            if (!WorkerAlive(group.Key.Pid, group.Key.Started) && portIsFree(group.Key.Port, group.Key.Protocol))
                foreach (var row in group) Delete(engine, row.Key);
        RemoveEmptySublayer(engine);
    });

    internal static void Purge() => Transact((engine, _) =>
    {
        var rules = ReadRules(engine);
        if (rules.Any(row => WorkerAlive(row.Pid, row.Started)))
            throw new IOException("A running worker still owns a protected network service. Stop the client before removing the filters.");
        foreach (var row in rules) Delete(engine, row.Key);
        Check(FwpmSubLayerDeleteByKey0(engine, in SublayerKey), SublayerNotFound);
    });

    private sealed class Lease(List<Guid> keys) : IDisposable
    {
        public void Dispose() => Transact((engine, _) =>
        {
            foreach (var key in keys) Delete(engine, key);
            RemoveEmptySublayer(engine);
        });
    }

    private static void Delete(nint engine, Guid key) => Check(FwpmFilterDeleteByKey0(engine, in key), FilterNotFound);

    private static void RemoveEmptySublayer(nint engine)
    {
        var result = FwpmSubLayerDeleteByKey0(engine, in SublayerKey);
        if (result != InUse) Check(result, SublayerNotFound);
    }

    private static bool WorkerAlive(int pid, long started)
    {
        try { using var process = Process.GetProcessById(pid); return !process.HasExited && process.StartTime.ToFileTimeUtc() == started; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (Win32Exception) { return true; }
    }

    private sealed record Rule(Guid Key, int Port, NetworkServiceProtocol Protocol, int Pid, long Started, byte[] Owner);

    private static List<Rule> ReadRules(nint engine)
    {
        var rules = new List<Rule>();
        var lookup = FwpmSubLayerGetByKey0(engine, in SublayerKey, out var sublayer);
        if (lookup == SublayerNotFound) return rules;
        Check(lookup);
        try
        {
            var layer = Marshal.PtrToStructure<Sublayer>(sublayer);
            if (layer.Provider != 0 || (layer.Flags & Persistent) == 0)
                throw new InvalidDataException("The existing Windows network service sublayer has unexpected ownership or lifetime.");
        }
        finally { FwpmFreeMemory0(ref sublayer); }
        foreach (var layer in new[] { ConnectV4, ConnectV6, ReceiveV4, ReceiveV6 })
        {
            var template = new EnumTemplate { Layer = layer, Flags = 0x10, ActionMask = uint.MaxValue };
            var status = FwpmFilterCreateEnumHandle0(engine, ref template, out var enumeration);
            Check(status);
            try
            {
                uint count;
                do
                {
                    Check(FwpmFilterEnum0(engine, enumeration, 128, out var entries, out count));
                    try
                    {
                        for (int i = 0; i < count; i++)
                        {
                            var native = Marshal.PtrToStructure<Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                            if (native.Provider != 0 || native.Sublayer != SublayerKey) continue;
                            if (native.ProviderData.Length is < 24 or > 84 || native.ProviderData.Data == 0)
                                throw new InvalidDataException("An installed BijouShare network rule is invalid.");
                            var metadata = new byte[native.ProviderData.Length];
                            Marshal.Copy(native.ProviderData.Data, metadata, 0, metadata.Length);
                            var pid = BinaryPrimitives.ReadInt32LittleEndian(metadata);
                            var port = BinaryPrimitives.ReadUInt16LittleEndian(metadata.AsSpan(4));
                            var protocol = (NetworkServiceProtocol)metadata[6];
                            var started = BinaryPrimitives.ReadInt64LittleEndian(metadata.AsSpan(8));
                            var owner = metadata[16..];
                            if (metadata[7] != 1 || port == 0 || pid <= 0 || started <= 0 || protocol is not (NetworkServiceProtocol.Tcp or NetworkServiceProtocol.Udp) ||
                                new SecurityIdentifier(owner, 0).BinaryLength != owner.Length)
                                throw new InvalidDataException("A network listener rule has invalid ownership data.");
                            rules.Add(new(native.Key, port, protocol, pid, started, owner));
                        }
                    }
                    finally { if (entries != 0) FwpmFreeMemory0(ref entries); }
                } while (count == 128);
            }
            finally { FwpmFilterDestroyEnumHandle0(engine, enumeration); }
        }
        return rules;
    }

    private static void Transact(Action<nint, Memory> action)
    {
        Check(FwpmEngineOpen0(0, 10, 0, 0, out var engine)); // RPC_C_AUTHN_WINNT
        try
        {
            using var memory = new Memory();
            Check(FwpmTransactionBegin0(engine, 0));
            try { action(engine, memory); Check(FwpmTransactionCommit0(engine)); }
            catch { FwpmTransactionAbort0(engine); throw; }
        }
        finally { FwpmEngineClose0(engine); }
    }

    private static void Check(uint code, uint ignored = 0)
    {
        if (code != 0 && code != ignored)
            throw new Win32Exception((int)code, $"Windows Filtering Platform returned 0x{code:x8}.");
    }

    private sealed class Memory : IDisposable
    {
        private readonly List<nint> allocations = [];
        private nint Keep(nint pointer) { allocations.Add(pointer); return pointer; }
        internal nint String(string value) => Keep(Marshal.StringToHGlobalUni(value));
        internal nint Put<T>(T value) where T : unmanaged => Array([value]);
        internal nint Array<T>(T[] values) where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            var pointer = Keep(Marshal.AllocHGlobal(checked(size * values.Length)));
            for (int i = 0; i < values.Length; i++) Marshal.StructureToPtr(values[i], pointer + i * size, false);
            return pointer;
        }
        internal nint Bytes(byte[] bytes)
        {
            var pointer = Keep(Marshal.AllocHGlobal(bytes.Length));
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }
        internal Blob Blob(byte[] bytes) => new() { Length = (uint)bytes.Length, Data = Bytes(bytes) };
        public void Dispose() { foreach (var pointer in allocations) Marshal.FreeHGlobal(pointer); }
    }

    // WinSDK fwpmtypes.h and fwptypes.h native layout. The value and context unions are
    // pointer-sized and 16 bytes respectively on this x64-only application.
    [StructLayout(LayoutKind.Sequential)] private struct Display { public nint Name, Description; }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public uint Length; public nint Data; }
    [StructLayout(LayoutKind.Sequential)] private struct Value(uint type, nint data) { public uint Type = type; public nint Data = data; }
    [StructLayout(LayoutKind.Sequential)] private struct Condition(Guid key, uint type, nint data)
    { public Guid Key = key; public uint Match = 0; public Value Value = new(type, data); }
    [StructLayout(LayoutKind.Sequential)] private struct Sublayer
    { public Guid Key; public Display Display; public ushort Flags; public nint Provider; public Blob Data; public ushort Weight; }
    [StructLayout(LayoutKind.Sequential)] private struct ActionType { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] private struct Context { [FieldOffset(0)] public ulong Raw; }
    [StructLayout(LayoutKind.Sequential)] private struct Filter
    {
        public Guid Key; public Display Display; public uint Flags; public nint Provider; public Blob ProviderData;
        public Guid Layer, Sublayer; public Value Weight; public uint ConditionCount; public nint Conditions;
        public ActionType Action; public Context Context; public nint Reserved; public ulong FilterId; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] private struct EnumTemplate
    {
        public nint Provider; public Guid Layer; public uint EnumType, Flags; public nint Context;
        public uint ConditionCount; public nint Conditions; public uint ActionMask; public nint CalloutKey;
    }

    private const string Dll = "fwpuclnt.dll";
    [DllImport(Dll)] private static extern uint FwpmEngineOpen0(nint serverName, uint auth, nint identity, nint session, out nint engine);
    [DllImport(Dll)] private static extern uint FwpmEngineClose0(nint engine);
    [DllImport(Dll)] private static extern uint FwpmTransactionBegin0(nint engine, uint flags);
    [DllImport(Dll)] private static extern uint FwpmTransactionCommit0(nint engine);
    [DllImport(Dll)] private static extern uint FwpmTransactionAbort0(nint engine);
    [DllImport(Dll)] private static extern uint FwpmSubLayerAdd0(nint engine, ref Sublayer sublayer, nint descriptor);
    [DllImport(Dll)] private static extern uint FwpmSubLayerGetByKey0(nint engine, in Guid key, out nint sublayer);
    [DllImport(Dll)] private static extern uint FwpmSubLayerDeleteByKey0(nint engine, in Guid key);
    [DllImport(Dll)] private static extern uint FwpmFilterAdd0(nint engine, ref Filter filter, nint descriptor, out ulong id);
    [DllImport(Dll)] private static extern uint FwpmFilterDeleteByKey0(nint engine, in Guid key);
    [DllImport(Dll)] private static extern uint FwpmFilterCreateEnumHandle0(nint engine, ref EnumTemplate template, out nint enumeration);
    [DllImport(Dll)] private static extern uint FwpmFilterDestroyEnumHandle0(nint engine, nint enumeration);
    [DllImport(Dll)] private static extern uint FwpmFilterEnum0(nint engine, nint enumeration, uint requested, out nint entries, out uint count);
    [DllImport(Dll)] private static extern void FwpmFreeMemory0(ref nint pointer);
}
