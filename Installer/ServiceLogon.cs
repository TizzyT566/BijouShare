using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace BijouShare.Installer
{
    internal static class ServiceLogon
    {
        private const string Right = "SeServiceLogonRight";
        private const uint AccountNotFound = 0xc0000034;

        internal static bool GrantIfMissing(SecurityIdentifier account) { return Change(account, true); }
        internal static void Remove(SecurityIdentifier account) { Change(account, false); }

        private static bool Change(SecurityIdentifier account, bool grant)
        {
            var sid = new byte[account.BinaryLength];
            account.GetBinaryForm(sid, 0);
            IntPtr policy;
            var attributes = new ObjectAttributes { Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)) };
            const uint lookupNames = 0x800, createAccount = 0x10;
            Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, lookupNames | (grant ? createAccount : 0), out policy));
            try
            {
                if (HasDirectGrant(policy, sid) == grant) return false;
                var right = new UnicodeString { Length = (ushort)(Right.Length * 2), MaximumLength = (ushort)((Right.Length + 1) * 2),
                    Buffer = Marshal.StringToHGlobalUni(Right) };
                try
                {
                    Check(grant ? LsaAddAccountRights(policy, sid, ref right, 1) :
                        LsaRemoveAccountRights(policy, sid, false, ref right, 1));
                    return true;
                }
                finally { Marshal.FreeHGlobal(right.Buffer); }
            }
            finally { LsaClose(policy); }
        }

        private static bool HasDirectGrant(IntPtr policy, byte[] sid)
        {
            IntPtr rights; uint count;
            uint status = LsaEnumerateAccountRights(policy, sid, out rights, out count);
            if (status == AccountNotFound) return false;
            Check(status);
            try
            {
                int size = Marshal.SizeOf(typeof(UnicodeString));
                for (int i = 0; i < count; ++i)
                {
                    var name = (UnicodeString)Marshal.PtrToStructure(IntPtr.Add(rights, i * size), typeof(UnicodeString));
                    if (String.Equals(Right, Marshal.PtrToStringUni(name.Buffer, name.Length / 2), StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            finally { LsaFreeMemory(rights); }
        }

        private static void Check(uint status)
        {
            if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public uint Length;
            public IntPtr RootDirectory, ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor, SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }

        [DllImport("advapi32.dll")] private static extern uint LsaOpenPolicy(IntPtr system, ref ObjectAttributes attributes, uint access, out IntPtr policy);
        [DllImport("advapi32.dll")] private static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, ref UnicodeString rights, uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool all, ref UnicodeString rights, uint count);
        [DllImport("advapi32.dll")] private static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("advapi32.dll")] private static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll")] private static extern uint LsaClose(IntPtr policy);
    }
}
