using System;
using System.ComponentModel;
using System.Drawing;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Windows.Forms;

namespace BijouShare.Installer
{
    internal sealed class ServerInstallAccount : IDisposable
    {
        private readonly SecurityIdentifier sid;
        private readonly string user;
        private bool grantedLogonRight;
        internal string AccountName { get { return Environment.MachineName + "\\" + user; } }
        internal SecureString Password { get; private set; }

        private ServerInstallAccount(string user, SecurityIdentifier sid, SecureString password)
        {
            this.user = user;
            this.sid = sid;
            Password = password;
        }

        internal void KeepLogonRight() { grantedLogonRight = false; }

        public void Dispose()
        {
            if (Password != null) { Password.Dispose(); Password = null; }
            if (grantedLogonRight)
            {
                ServiceLogon.Remove(sid);
                grantedLogonRight = false;
            }
        }

        internal static bool Prompt(out ServerInstallAccount account)
        {
            return Prompt(out account, false);
        }

        internal static bool Prompt(out ServerInstallAccount account, bool administratorOnly)
        {
            account = null;
            string name = null, problem = null;
            SecurityIdentifier accountSid = null;
            try { FindAdministrator(out name, out accountSid, out problem); }
            catch (Exception ex)
            {
                if (!(ex is ManagementException || ex is COMException || ex is UnauthorizedAccessException)) throw;
                problem = "Windows could not look up the local Administrator account. " + ex.Message;
            }
            using (var dialog = new AccountDialog(administratorOnly, name, accountSid, problem))
            {
                if (dialog.ShowDialog() != DialogResult.OK) return false;
                account = dialog.Selection;
                return true;
            }
        }

        private static void FindAdministrator(out string name, out SecurityIdentifier sid, out string problem)
        {
            name = null; sid = null;
            problem = "This computer has no local built-in Administrator account.";
            using (var computer = new ManagementObject("Win32_ComputerSystem.Name='" + Environment.MachineName + "'"))
            {
                // Domain controllers have a domain RID 500 account, not a machine-local one.
                if (Convert.ToInt32(computer["DomainRole"]) >= 4) return;
            }
            using (var query = new ManagementObjectSearcher(
                "SELECT Name, Domain, Disabled, SID FROM Win32_UserAccount WHERE LocalAccount = TRUE AND SID LIKE '%-500'"))
            using (var rows = query.Get())
            {
                foreach (ManagementObject row in rows)
                using (row)
                {
                    if (!String.Equals((string)row["Domain"], Environment.MachineName, StringComparison.OrdinalIgnoreCase)) continue;
                    var id = new SecurityIdentifier((string)row["SID"]);
                    if (!id.IsWellKnown(WellKnownSidType.AccountAdministratorSid)) continue;
                    name = (string)row["Name"];
                    sid = id;
                    problem = (bool)row["Disabled"] ? "The local Administrator account is disabled in Windows." : null;
                    return;
                }
            }
        }

        private sealed class AccountDialog : Form
        {
            private readonly string user;
            private readonly SecurityIdentifier sid;
            private readonly RadioButton administrator;
            private readonly TextBox password;
            internal ServerInstallAccount Selection { get; private set; }

            internal AccountDialog(bool administratorOnly, string user, SecurityIdentifier sid, string problem)
            {
                this.user = user; this.sid = sid;
                Text = "BijouShare Server Setup";
                Font = SystemFonts.MessageBoxFont;
                AutoScaleMode = AutoScaleMode.Font;
                AutoSize = true;
                AutoSizeMode = AutoSizeMode.GrowAndShrink;
                FormBorderStyle = FormBorderStyle.FixedDialog;
                StartPosition = FormStartPosition.CenterScreen;
                MaximizeBox = MinimizeBox = false;
                ShowInTaskbar = true;
                var layout = new TableLayoutPanel { AutoSize = true, ColumnCount = 1, Padding = new Padding(14) };
                Controls.Add(layout);
                layout.Controls.Add(LabelFor(administratorOnly ? "Restart BijouShare Server as the local Administrator" :
                    "Choose the Windows account that will run BijouShare Server."));
                if (!administratorOnly)
                    layout.Controls.Add(new RadioButton { Text = "&Local Service (default)", AutoSize = true, Checked = true });
                administrator = new RadioButton { Text = user == null ? "Local &Administrator" :
                    "Local &Administrator (" + Environment.MachineName + "\\" + user.Replace("&", "&&") + ")",
                    AutoSize = true, Enabled = problem == null, Checked = administratorOnly && problem == null };
                layout.Controls.Add(administrator);
                layout.Controls.Add(LabelFor(problem ?? "This account gives the server local administrator privileges."));
                var label = LabelFor("&Windows account password");
                layout.Controls.Add(label);
                password = new TextBox { UseSystemPasswordChar = true, Width = 380, MaxLength = 256,
                    AccessibleName = "Windows account password" };
                layout.Controls.Add(password);
                layout.Controls.Add(LabelFor("Use the Windows password for this account. The BijouShare web console has a separate sign-in."));
                var actions = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.Right, WrapContents = false,
                    Padding = new Padding(0, 7, 0, 0) };
                var ok = new Button { AutoSize = true, Text = administratorOnly ? "Restart service" : "Continue",
                    Enabled = !administratorOnly || problem == null };
                var cancel = new Button { AutoSize = true, Text = "Cancel", DialogResult = DialogResult.Cancel };
                actions.Controls.Add(ok); actions.Controls.Add(cancel); layout.Controls.Add(actions);
                AcceptButton = ok; CancelButton = cancel;
                password.Enabled = label.Enabled = administrator.Checked;
                administrator.CheckedChanged += delegate {
                    password.Enabled = label.Enabled = administrator.Checked;
                    if (administrator.Checked) password.Focus(); else ClearPassword();
                };
                FormClosing += delegate { ClearPassword(); };
                ok.Click += delegate { Submit(); };
            }

            private static Label LabelFor(string text)
            {
                return new Label { Text = text, AutoSize = true, MaximumSize = new Size(415, 0), Margin = new Padding(3, 6, 3, 4) };
            }

            private void Submit()
            {
                if (!administrator.Checked) { DialogResult = DialogResult.OK; return; }
                var typed = ReadPassword(password);
                ClearPassword();
                if (typed.Length == 0)
                {
                    typed.Dispose();
                    MessageBox.Show(this, "Enter the Windows account password.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    password.Focus(); return;
                }
                var candidate = new ServerInstallAccount(user, sid, typed);
                try
                {
                    candidate.CheckServiceLogon();
                    Selection = candidate;
                }
                catch (Exception error)
                {
                    candidate.Dispose();
                    if (!(error is Win32Exception || error is InvalidOperationException)) throw;
                    MessageBox.Show(this, error.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    password.Focus(); return;
                }
                DialogResult = DialogResult.OK;
            }

            private void ClearPassword()
            {
                if (password.IsHandleCreated) SendMessageW(password.Handle, 0x000C /* WM_SETTEXT */, IntPtr.Zero, IntPtr.Zero);
            }
        }

        // Copy directly out of the native masked edit control, without obtaining TextBox.Text.
        internal static SecureString ReadPassword(TextBox edit)
        {
            int capacity = edit.MaxLength + 1;
            IntPtr buffer = Marshal.AllocHGlobal(capacity * sizeof(char));
            var result = new SecureString();
            try
            {
                int count = (int)SendMessageW(edit.Handle, 0x000D /* WM_GETTEXT */, (IntPtr)capacity, buffer);
                for (int i = 0; i < count; ++i) result.AppendChar((char)Marshal.ReadInt16(buffer, i * sizeof(char)));
                result.MakeReadOnly();
                return result;
            }
            catch { result.Dispose(); throw; }
            finally
            {
                for (int i = 0; i < capacity; ++i) Marshal.WriteInt16(buffer, i * sizeof(char), 0);
                Marshal.FreeHGlobal(buffer);
            }
        }

        private void CheckServiceLogon()
        {
            IntPtr secret = Marshal.SecureStringToGlobalAllocUnicode(Password);
            try
            {
                const int service = 5, interactive = 2, logonTypeNotGranted = 1385;
                int error = CheckLogon(secret, service);
                if (error == 0) return;
                if (error != logonTypeNotGranted) throw new Win32Exception(error);
                // Validate the credentials before editing local policy. A direct grant cannot override a deny.
                error = CheckLogon(secret, interactive);
                if (error != 0) throw new Win32Exception(error);
                grantedLogonRight = ServiceLogon.GrantIfMissing(sid);
                error = CheckLogon(secret, service);
                if (error == logonTypeNotGranted)
                    throw new InvalidOperationException("Windows policy prevents this account from logging on as a service. Check the local or domain service logon policy.");
                if (error != 0) throw new Win32Exception(error);
            }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
        }

        private int CheckLogon(IntPtr password, int logonType)
        {
            IntPtr token;
            if (!LogonUserW(user, Environment.MachineName, password, logonType, 0, out token))
                return Marshal.GetLastWin32Error();
            try
            {
                using (var identity = new WindowsIdentity(token))
                    if (!sid.Equals(identity.User)) throw new InvalidOperationException("The Windows account identity changed. Reopen setup.");
                return 0;
            }
            finally { CloseHandle(token); }
        }

        [DllImport("user32.dll", ExactSpelling = true)]
        private static extern IntPtr SendMessageW(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool LogonUserW(string user, string domain, IntPtr password, int type, int provider, out IntPtr token);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    }
}
