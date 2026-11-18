using System.ComponentModel;
using System.Runtime.InteropServices;
using static BijouShare.Shared.TrayNative;

namespace BijouShare.Shared;

// Only explicitly authored, non-sensitive text is eligible for a desktop notification.
internal sealed class TrayOpenException(string message) : IOException(message);

internal sealed class WindowsTrayIcon : IDisposable
{
    private const uint CallbackMessage = 0x8001; // WM_APP + 1
    private const uint OpenFailed = 0x8002;
    private const uint Close = 0x0010, Timer = 0x0113;
    private const uint Add = 0, Modify = 1, Delete = 2, SetFocus = 3, SetVersion = 4;
    private readonly string title;
    private readonly Func<CancellationToken, Task> openConsole;
    private readonly CancellationTokenSource stopping = new();
    private readonly Action<Exception>? onError;
    private readonly Action? onExit;
    private readonly Thread thread;
    private readonly SubclassProcedure windowProcedure;
    private readonly TaskCompletionSource<nint> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task Completion => closed.Task;
    private uint taskbarCreated;
    private IconData icon;
    private int disposed;
    private int opening;
    private string? pendingNotice;
    private long lastActivation = -60_000;

    private WindowsTrayIcon(string title, Func<CancellationToken, Task> openConsole, Action<Exception>? onError, Action? onExit)
    {
        this.title = title;
        this.openConsole = openConsole;
        this.onError = onError;
        this.onExit = onExit;
        windowProcedure = HandleMessage;
        thread = new Thread(Run) { IsBackground = true, Name = title + " tray" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
    }

    public static WindowsTrayIcon Start(string title, Action openConsole, Action<Exception>? onError = null, Action? onExit = null) =>
        new(title, _ => { openConsole(); return Task.CompletedTask; }, onError, onExit);

    public static WindowsTrayIcon Start(string title, Func<CancellationToken, Task> openConsole, Action<Exception>? onError = null, Action? onExit = null) =>
        new(title, openConsole, onError, onExit);

    public static void DetachPrivateConsole()
    {
        if (Console.IsOutputRedirected || Console.IsErrorRedirected || Console.IsInputRedirected)
            return;
        var processes = new uint[1];
        if (GetConsoleProcessList(processes, 1) == 1 && processes[0] == Environment.ProcessId)
            FreeConsole();
    }

    private void Run()
    {
        nint window = 0, smallIcon = 0;
        try
        {
            // TaskbarCreated is broadcast only to top-level windows, not message-only windows.
            window = CreateWindowExW(0x80, "STATIC", title, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0);
            if (window == 0 || !SetWindowSubclass(window, windowProcedure, 1, 0))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not create the tray window.");
            taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
            if (taskbarCreated == 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            // Explorer may run at normal integrity while the server console runs elevated.
            ChangeWindowMessageFilterEx(window, taskbarCreated, 1, 0);
            ChangeWindowMessageFilterEx(window, CallbackMessage, 1, 0);

            ExtractIconExW(typeof(WindowsTrayIcon).Assembly.Location, 0, 0, out smallIcon, 1);
            icon = new IconData
            {
                Size = (uint)Marshal.SizeOf<IconData>(), Window = window, Id = 1, Callback = CallbackMessage,
                Icon = smallIcon != 0 ? smallIcon : LoadIconW(0, 32512), Tooltip = title
            };
            ready.SetResult(window);
            RegisterIcon();

            int result;
            while ((result = GetMessageW(out var message, 0, 0, 0)) > 0)
            {
                TranslateMessage(in message);
                DispatchMessageW(in message);
            }
            if (result < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        catch (Exception error)
        {
            Report(error);
        }
        finally
        {
            ready.TrySetResult(0);
            if (window != 0)
            {
                if (icon.Window != 0) Shell_NotifyIconW(Delete, in icon);
                RemoveWindowSubclass(window, windowProcedure, 1);
                DestroyWindow(window);
            }
            if (smallIcon != 0) DestroyIcon(smallIcon);
            closed.TrySetResult();
        }
    }

    private void RegisterIcon()
    {
        icon.Flags = 0x01 | 0x02 | 0x04 | 0x80; // NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
        if (Shell_NotifyIconW(Add, in icon) || Shell_NotifyIconW(Modify, in icon))
        {
            icon.Version = 4;
            Shell_NotifyIconW(SetVersion, in icon);
            KillTimer(icon.Window, 1);
        }
        else
        {
            // A user worker can start before Explorer has created its notification area.
            SetTimer(icon.Window, 1, 3000, 0);
        }
    }

    private nint HandleMessage(nint window, uint message, nuint wParam, nint lParam, nuint subclassId, nuint data)
    {
        try
        {
            if (message == Close)
            {
                EndMenu();
                PostQuitMessage(0);
                return 0;
            }
            if (message == OpenFailed)
            {
                var text = Interlocked.Exchange(ref pendingNotice, null);
                if (text is not null && Volatile.Read(ref disposed) == 0)
                {
                    var notice = icon;
                    notice.Flags = 0x10; // NIF_INFO
                    notice.InfoTitle = title;
                    notice.Info = text;
                    notice.InfoFlags = 0x82; // NIIF_WARNING | NIIF_RESPECT_QUIET_TIME
                    Shell_NotifyIconW(Modify, in notice);
                }
                return 0;
            }
            if (message == taskbarCreated || (message == Timer && wParam == 1))
            {
                if (icon.Window != 0) RegisterIcon();
                return 0;
            }
            if (message == CallbackMessage && Volatile.Read(ref disposed) == 0)
            {
                switch ((uint)lParam & 0xffff)
                {
                    case 0x0202: // WM_LBUTTONUP
                    case 0x0400: // NIN_SELECT
                    case 0x0401: // NIN_KEYSELECT
                        var now = Environment.TickCount64;
                        if (now - lastActivation >= GetDoubleClickTime())
                        {
                            lastActivation = now;
                            OpenConsole();
                        }
                        break;
                    case 0x007b: // WM_CONTEXTMENU, including Shift+F10
                        ShowMenu(window);
                        break;
                }
                return 0;
            }
        }
        catch (Exception error)
        {
            Report(error);
        }
        return DefSubclassProc(window, message, wParam, lParam);
    }

    private void OpenConsole()
    {
        if (Interlocked.Exchange(ref opening, 1) == 0)
            _ = OpenConsoleAsync(icon.Window, stopping.Token);
    }

    private async Task OpenConsoleAsync(nint window, CancellationToken token)
    {
        try { await openConsole(token).ConfigureAwait(false); }
        catch (Exception error)
        {
            if (token.IsCancellationRequested) return;
            Report(error);
            Interlocked.Exchange(ref pendingNotice, OpenFailureNotice(error));
            PostMessageW(window, OpenFailed, 0, 0);
        }
        finally { Volatile.Write(ref opening, 0); }
    }

    internal static string OpenFailureNotice(Exception error) => error is TrayOpenException ? error.Message :
        "Could not open the management console. Check that the application is running and try again.";

    private void ShowMenu(nint window)
    {
        var menu = CreatePopupMenu();
        if (menu == 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            AppendMenuW(menu, 0, 1, "Open " + title);
            if (onExit is not null) AppendMenuW(menu, 0, 2, "Exit");
            SetMenuDefaultItem(menu, 1, false);
            var identifier = new IconIdentifier { Size = (uint)Marshal.SizeOf<IconIdentifier>(), Window = window, Id = icon.Id };
            GetCursorPos(out var anchor);
            if (Shell_NotifyIconGetRect(in identifier, out var bounds) == 0)
                anchor = new Point { X = bounds.Left, Y = bounds.Top };
            SetForegroundWindow(window);
            var command = TrackPopupMenuEx(menu, 0x0182, anchor.X, anchor.Y, window, 0); // return command, no WM_COMMAND, both buttons
            PostMessageW(window, 0, 0, 0);
            if (command == 1) OpenConsole();
            else if (command == 2) onExit?.Invoke();
            else Shell_NotifyIconW(SetFocus, in icon);
        }
        finally { DestroyMenu(menu); }
    }

    private void Report(Exception error)
    {
        // Logging must never unwind through an unmanaged window procedure during shutdown.
        try { onError?.Invoke(error); } catch (Exception) { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopping.Cancel();
        var window = ready.Task.GetAwaiter().GetResult();
        if (window != 0 && thread.IsAlive)
            PostMessageW(window, Close, 0, 0);
        if (Thread.CurrentThread != thread) thread.Join(TimeSpan.FromSeconds(5));
        stopping.Dispose();
    }
}
