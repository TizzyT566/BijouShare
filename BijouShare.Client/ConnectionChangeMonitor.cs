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
    private long resumeGraceUntil;
    private readonly SemaphoreSlim changed = new(0);
    private readonly bool watchingAddresses, watchingAvailability;

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
            watchingAddresses = true;
            NetworkChange.NetworkAvailabilityChanged += OnAvailabilityChange;
            watchingAvailability = true;
        }
        catch (NetworkInformationException exception)
        {
            logger.LogWarning(exception, "Windows address notifications are unavailable. Connection checks will use the heartbeat.");
        }
    }

    internal Change TakeChanges() => (Change)Interlocked.Exchange(ref pending, 0);
    internal Task WaitAsync(CancellationToken token) => changed.WaitAsync(TimeSpan.FromSeconds(1), token);
    internal void NoteResume(long tick) => Interlocked.Exchange(ref resumeGraceUntil, tick + 15_000);
    internal bool WaitingForVolume(long tick) => tick < Interlocked.Read(ref resumeGraceUntil);

    private void Signal(Change flags)
    {
        if (Interlocked.Or(ref pending, (int)flags) == 0)
        {
            try { changed.Release(); }
            catch (ObjectDisposedException) { } // A final Windows notification can race shutdown.
        }
    }

    private uint OnPowerChange(nint context, uint type, nint setting)
    {
        // Windows sends RESUMEAUTOMATIC on every resume, even without user input.
        if (type == ResumeAutomatic)
        {
            NoteResume(Environment.TickCount64);
            Signal(Change.Resume);
        }
        return 0;
    }

    private void OnNetworkChange(object? sender, EventArgs args) => Signal(Change.Network);
    private void OnAvailabilityChange(object? sender, NetworkAvailabilityEventArgs args) => Signal(Change.Network);

    public void Dispose()
    {
        if (watchingAddresses)
            NetworkChange.NetworkAddressChanged -= OnNetworkChange;
        if (watchingAvailability)
            NetworkChange.NetworkAvailabilityChanged -= OnAvailabilityChange;
        changed.Dispose();
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
