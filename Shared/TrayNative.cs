using System.Runtime.InteropServices;

namespace BijouShare.Shared;

internal static class TrayNative
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Point { public int X, Y; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Rect { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Message
    {
        public nint Window;
        public uint Id;
        public nuint WParam;
        public nint LParam;
        public uint Time;
        public Point Cursor;
        public uint Private;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct IconData
    {
        public uint Size;
        public nint Window;
        public uint Id, Flags, Callback;
        public nint Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string? Tooltip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string? Info;
        public uint Version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string? InfoTitle;
        public uint InfoFlags;
        public Guid Guid;
        public nint BalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IconIdentifier
    {
        public uint Size;
        public nint Window;
        public uint Id;
        public Guid Guid;
    }

    internal delegate nint SubclassProcedure(nint window, uint message, nuint wParam, nint lParam, nuint subclassId, nuint data);

    [DllImport("kernel32.dll")] internal static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
    [DllImport("kernel32.dll")] internal static extern bool FreeConsole();
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint CreateWindowExW(uint exStyle, string className, string title, uint style, int x, int y,
        int width, int height, nint parent, nint menu, nint instance, nint parameter);
    [DllImport("comctl32.dll", SetLastError = true)]
    internal static extern bool SetWindowSubclass(nint window, SubclassProcedure procedure, nuint id, nuint data);
    [DllImport("comctl32.dll")]
    internal static extern bool RemoveWindowSubclass(nint window, SubclassProcedure procedure, nuint id);
    [DllImport("comctl32.dll")] internal static extern nint DefSubclassProc(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint RegisterWindowMessageW(string name);
    [DllImport("user32.dll")] internal static extern bool ChangeWindowMessageFilterEx(nint window, uint message, uint action, nint changeInfo);
    [DllImport("shell32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern uint ExtractIconExW(string file, int index, nint largeIcon, out nint smallIcon, uint count);
    [DllImport("user32.dll", ExactSpelling = true)] internal static extern nint LoadIconW(nint module, nint id);
    [DllImport("user32.dll")] internal static extern bool DestroyIcon(nint icon);
    [DllImport("shell32.dll", ExactSpelling = true)]
    internal static extern bool Shell_NotifyIconW(uint operation, in IconData data);
    [DllImport("shell32.dll", ExactSpelling = true)]
    internal static extern int Shell_NotifyIconGetRect(in IconIdentifier identifier, out Rect rect);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern int GetMessageW(out Message message, nint window, uint first, uint last);
    [DllImport("user32.dll")] internal static extern bool TranslateMessage(in Message message);
    [DllImport("user32.dll", ExactSpelling = true)] internal static extern nint DispatchMessageW(in Message message);
    [DllImport("user32.dll", ExactSpelling = true)] internal static extern bool PostMessageW(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll")] internal static extern void PostQuitMessage(int code);
    [DllImport("user32.dll")] internal static extern bool DestroyWindow(nint window);
    [DllImport("user32.dll")] internal static extern nuint SetTimer(nint window, nuint id, uint interval, nint callback);
    [DllImport("user32.dll")] internal static extern bool KillTimer(nint window, nuint id);
    [DllImport("user32.dll")] internal static extern uint GetDoubleClickTime();
    [DllImport("user32.dll", SetLastError = true)] internal static extern nint CreatePopupMenu();
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern bool AppendMenuW(nint menu, uint flags, nuint id, string text);
    [DllImport("user32.dll")] internal static extern bool SetMenuDefaultItem(nint menu, uint item, bool byPosition);
    [DllImport("user32.dll")] internal static extern bool GetCursorPos(out Point cursor);
    [DllImport("user32.dll")] internal static extern bool SetForegroundWindow(nint window);
    [DllImport("user32.dll")] internal static extern uint TrackPopupMenuEx(nint menu, uint flags, int x, int y, nint window, nint parameters);
    [DllImport("user32.dll")] internal static extern bool EndMenu();
    [DllImport("user32.dll")] internal static extern bool DestroyMenu(nint menu);
}
