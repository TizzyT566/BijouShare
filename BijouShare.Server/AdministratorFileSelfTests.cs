using System.Security.AccessControl;
using System.Security.Principal;
using BijouShare.Shared;

namespace BijouShare.Server;

internal static class AdministratorFileSelfTests
{
    public static void Run(string root, StateStore store, FileService files, Action<bool, string> check)
    {
        var shareId = Guid.NewGuid();
        var groupId = Guid.NewGuid();
        var session = Guid.NewGuid();
        var directory = Directory.CreateDirectory(Path.Combine(root, "administrator-files")).FullName;
        var file = Path.Combine(directory, "open.txt");
        using var key = KeyAgreement.NewKey();
        var publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        var registration = TestRegistration.Create("Manually approved device", publicKey);
        var deviceId = TestRegistration.RecordId(registration.DeviceId);
        try
        {
            store.Update(state => { state.Groups.Add(new(groupId, "Restricted writers")); return true; });
            store.QueueRegistration(registration);
            var device = store.ApproveDevice(deviceId, [StateStore.AdministratorGroupId, groupId], registration.DeviceId);
            store.Update(state => { state.Shares.Add(new(shareId, "NewShare", directory, true)); return true; });
            RpcResponse Call(RpcRequest request) => files.Execute(session, deviceId, request, device);

            var listed = Call(new() { Operation = "List" }).Entries!.Single(entry => entry.Name == "NewShare");
            var opened = Call(new()
            {
                Operation = "Open", Path = "/NewShare/open.txt", Mode = FileMode.CreateNew,
                Access = AccessMask.GenericRead | AccessMask.GenericWrite, Share = FileShare.ReadWrite
            });
            check(listed.Permissions == Permission.FullControl &&
                Call(new() { Operation = "Write", Handle = opened.Handle, Data = [42] }).Length == 1,
                "A manually approved Administrator can discover and write to a share created after approval without a permission rule");

            RpcRequest CreateFolder(string name) => new()
            {
                Operation = "Open", Path = "/NewShare/" + name, Directory = true,
                Mode = FileMode.CreateNew, Access = AccessMask.ReadAttributes, Share = FileShare.ReadWrite | FileShare.Delete
            };
            var folder = Call(CreateFolder("Media"));
            Call(new() { Operation = "Close", Handle = folder.Handle });
            check(Directory.Exists(Path.Combine(directory, "Media")), "Administrator can create a folder on a writable share without a group rule");

            var storage = Directory.CreateDirectory(Path.Combine(directory, "storage"));
            var originalAcl = storage.GetAccessControl(AccessControlSections.Access);
            var restrictedAcl = storage.GetAccessControl(AccessControlSections.Access);
            using var account = WindowsIdentity.GetCurrent();
            restrictedAcl.AddAccessRule(new FileSystemAccessRule(account.User!, FileSystemRights.CreateDirectories, AccessControlType.Deny));
            storage.SetAccessControl(restrictedAcl);
            try
            {
                Call(CreateFolder("storage/New folder"));
                throw new InvalidOperationException("An Administrator created a folder through a Windows storage denial.");
            }
            catch (FileAccessDenial denied)
            {
                check(FileService.ErrorCode(denied) == "AccessDenied" && denied.InnerException is UnauthorizedAccessException &&
                    denied.Message.Contains(FileService.StorageAccount, StringComparison.Ordinal) &&
                    !Directory.Exists(Path.Combine(storage.FullName, "New folder")),
                    "NTFS can deny folder creation for Administrator and the diagnostic identifies the Windows storage account");
            }
            finally { storage.SetAccessControl(originalAcl); }

            File.WriteAllText(Path.Combine(directory, "restricted.txt"), "restricted");
            store.Update(state =>
            {
                state.Rules.Add(new(Guid.NewGuid(), groupId, shareId, "restricted.txt", Permission.None, Permission.WriteData, false)
                {
                    AdditionalScopes = [new("Media", Permission.None, Permission.CreateDirectories, true)]
                });
                return true;
            });
            var effective = Call(new() { Operation = "Security", Path = "/NewShare/restricted.txt" }).Permissions;
            check(effective == (Permission.FullControl & ~Permission.WriteData),
                "A second group's deny removes only the specified Administrator permission on its matching path");
            void ExpectDenied(RpcRequest request, string label)
            {
                try { Call(request); }
                catch (UnauthorizedAccessException) { check(true, label); return; }
                throw new InvalidOperationException("FAIL: " + label);
            }
            ExpectDenied(new() { Operation = "Open", Path = "/NewShare/restricted.txt", Access = AccessMask.WriteData },
                "A write denied by another group is rejected on the file server for an Administrator");
            ExpectDenied(CreateFolder("Media/New folder"), "An explicit CreateDirectories deny on a parent also applies to Administrator");
            check(!Directory.Exists(Path.Combine(directory, "Media", "New folder")), "Denied Administrator folder creation leaves storage untouched");
            store.Update(state =>
            {
                var index = state.Devices.FindIndex(item => item.Id == deviceId);
                return state.Devices[index] = state.Devices[index] with { GroupIds = [groupId] };
            });
            ExpectDenied(new() { Operation = "Write", Handle = opened.Handle, Data = [7] },
                "Removing Administrator membership immediately revokes a writer opened on the authenticated session");
            check(File.ReadAllBytes(file) is [42] && Call(new() { Operation = "List" }).Entries!.All(entry => entry.Name != "NewShare"),
                "Revocation preserves file contents and hides the share when remaining groups have no access");
        }
        finally
        {
            files.ReleaseSession(session);
            store.Update(state =>
            {
                state.Devices.RemoveAll(item => item.Id == deviceId);
                state.PendingDevices.RemoveAll(item => item.Id == deviceId);
                state.Groups.RemoveAll(item => item.Id == groupId);
                state.Shares.RemoveAll(item => item.Id == shareId);
                state.Rules.RemoveAll(item => item.ShareId == shareId);
                return true;
            });
        }
    }
}
