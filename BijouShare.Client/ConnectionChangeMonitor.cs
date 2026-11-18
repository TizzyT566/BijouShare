using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace BijouShare.Client;

// The power callback works for both an interactive client and a service in session zero.
// Callbacks only set flags. The drive worker performs network I/O on its own thread.
internal sealed class ConnectionChangeMonitor : IDisposable
{
    [Flags]
    internal enum Change { None = 0, Network = 1, Resume = 2 }

    private const uint DeviceNotifyCallback = 2;
    private const uint ResumeAutomatic = 0x12;
    private readonly ILogger logger;
    private GCHandle callbackRoot;
    private nint registration;
    private int pending;
    private readonly bool watchingNetwork;

    public ConnectionChangeMonitor(ILogger logger)
    {
        this.logger = logger;
        PowerCallback callback = OnPowerChange;
        callbackRoot = GCHandle.Alloc(callback);
        var recipient = new Recipient { Callback = Marshal.GetFunctionPointerForDelegate(callback) };
        var error = PowerRegisterSuspendResumeNotification(DeviceNotifyCallback, ref recipient, out registration);
        if (error != 0)
        {
            registration = 0;
            callbackRoot.Free();
            logger.LogWarning("Windows power notification registration returned {Error}. Wake detection will use the heartbeat.", error);
        }
        try
        {
            NetworkChange.NetworkAddressChanged += OnNetworkChange;
            watchingNetwork = true;
        }
        catch (NetworkInformationException exception)
        {
            logger.LogWarning(exception, "Windows address notifications are unavailable. Connection checks will use the heartbeat.");
        }
    }

    internal Change TakeChanges() => (Change)Interlocked.Exchange(ref pending, 0);

    private uint OnPowerChange(nint context, uint type, nint setting)
    {
        // Windows sends RESUMEAUTOMATIC on every resume, even without user input.
        if (type == ResumeAutomatic)
            Interlocked.Or(ref pending, (int)Change.Resume);
        return 0;
    }

    private void OnNetworkChange(object? sender, EventArgs args) => Interlocked.Or(ref pending, (int)Change.Network);

    public void Dispose()
    {
        if (watchingNetwork)
            NetworkChange.NetworkAddressChanged -= OnNetworkChange;
        var handle = Interlocked.Exchange(ref registration, 0);
        if (handle == 0)
            return;
        var error = PowerUnregisterSuspendResumeNotification(handle);
        if (error == 0)
            callbackRoot.Free();
        else
            logger.LogWarning("Windows power notification cleanup returned {Error}. Keeping the callback alive until process exit.", error);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint PowerCallback(nint context, uint type, nint setting);

    [StructLayout(LayoutKind.Sequential)]
    private struct Recipient
    {
        public nint Callback;
        public nint Context;
    }

    [DllImport("PowrProf.dll", ExactSpelling = true)]
    private static extern uint PowerRegisterSuspendResumeNotification(uint flags, ref Recipient recipient, out nint registration);

    [DllImport("PowrProf.dll", ExactSpelling = true)]
    private static extern uint PowerUnregisterSuspendResumeNotification(nint registration);
}
