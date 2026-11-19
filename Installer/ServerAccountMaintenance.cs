using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Windows.Forms;
using Microsoft.Win32;

namespace BijouShare.Installer
{
    internal static class ServerAccountMaintenance
    {
        private const string ServiceName = "BijouShare.Server";
        private const string Caption = "BijouShare Server Setup";
        private static readonly TimeSpan Wait = TimeSpan.FromSeconds(60);

        internal static int Run()
        {
            using (var service = new ServiceController(ServiceName))
            {
                // Check installation before asking for a machine credential.
                service.Refresh();
                if (service.Status == ServiceControllerStatus.StopPending)
                    service.WaitForStatus(ServiceControllerStatus.Stopped, Wait);
            }
            ServerInstallAccount account;
            if (!ServerInstallAccount.Prompt(out account, true)) return 1602;
            using (account) return Apply(account);
        }

        internal static int Apply(ServerInstallAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");
            using (var service = new ServiceController(ServiceName))
            using (var handle = service.ServiceHandle)
            {
                if (service.Status == ServiceControllerStatus.StopPending)
                    service.WaitForStatus(ServiceControllerStatus.Stopped, Wait);
                if (service.Status == ServiceControllerStatus.StartPending)
                    service.WaitForStatus(ServiceControllerStatus.Running, Wait);
                if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.Running)
                    throw new InvalidOperationException("Start or stop BijouShare Server in Services before changing its account.");
                string previous = ConfiguredAccount();
                bool wasActive = service.Status != ServiceControllerStatus.Stopped;
                bool changed = false;
                if (wasActive)
                {
                    // Send STOP only to this service. ServiceController.Stop() also stops dependents.
                    ServiceStatus ignored;
                    if (!ControlService(handle, 1, out ignored))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    service.WaitForStatus(ServiceControllerStatus.Stopped, Wait);
                }
                try
                {
                    IntPtr password = Marshal.SecureStringToGlobalAllocUnicode(account.Password);
                    try { SetAccount(handle, account.AccountName, password); }
                    finally { Marshal.ZeroFreeGlobalAllocUnicode(password); }
                    changed = true;
                    StartAndWait(service);
                    account.KeepLogonRight();
                }
                catch (Exception error)
                {
                    string recovery;
                    try
                    {
                        if (changed && !IsPasswordless(previous))
                        {
                            account.KeepLogonRight();
                            recovery = "Windows saved the new account. Check the service in Services and re-enter the desired account password if needed.";
                        }
                        else
                        {
                            if (changed) SetAccount(handle, previous, IntPtr.Zero);
                            if (wasActive) StartAndWait(service);
                            recovery = "The previous service account and running state were restored.";
                        }
                    }
                    catch (Exception restore)
                    {
                        // If rollback itself fails, preserve a right the new service configuration may need.
                        if (changed) account.KeepLogonRight();
                        recovery = "Check the Log On tab in Services. Recovery failed: " + restore.GetBaseException().Message;
                    }
                    throw new InvalidOperationException("Could not switch and restart BijouShare Server. " +
                        error.GetBaseException().Message + "\r\n\r\n" + recovery, error);
                }
            }
            MessageBox.Show(ServiceName + " is running as " + account.AccountName + ".", Caption,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        private static string ConfiguredAccount()
        {
            string account = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + ServiceName,
                "ObjectName", null) as string;
            if (String.IsNullOrEmpty(account)) throw new InvalidOperationException("Cannot read the installed server's service account.");
            return account;
        }

        private static bool IsPasswordless(string account)
        {
            return String.Equals(account, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(account, @"NT AUTHORITY\LocalService", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(account, @"NT AUTHORITY\NetworkService", StringComparison.OrdinalIgnoreCase);
        }

        private static void StartAndWait(ServiceController service)
        {
            service.Refresh();
            if (service.Status == ServiceControllerStatus.Stopped) service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, Wait);
        }

        private static void SetAccount(SafeHandle handle, string account, IntPtr password)
        {
            const uint unchanged = UInt32.MaxValue;
            if (!ChangeServiceConfigW(handle, unchanged, unchanged, unchanged, null, null, IntPtr.Zero, null, account, password, null))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatus
        {
            public uint Type, State, Controls, Error, SpecificError, Checkpoint, WaitHint;
        }
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool ControlService(SafeHandle service, uint control, out ServiceStatus status);
        [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfigW(SafeHandle service, uint type, uint start, uint error,
            string binary, string group, IntPtr tag, string dependencies, string account, IntPtr password, string displayName);
    }
}
