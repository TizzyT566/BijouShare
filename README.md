# BijouShare

A C#/.NET 10 Windows solution containing exactly **two executable projects**:

| Project | Role |
| --- | --- |
| `BijouShare.Server` | Windows service, encrypted LAN file server, device approval, groups/shares/rules, and an ASP.NET Core administration UI. |
| `BijouShare.Client` | Windows session launcher and per-user client. Each Windows account has its own device identity, server connections and Dokany drive letters. |

`Shared/` contains the protocol and storage helpers compiled into both projects. Both services can also run interactively for setup and troubleshooting.

Server folders use `ServerName_<first16hex>`. The client checks the server’s public keys against the full 64-character fingerprint in its connection link. Renaming the server changes the folder prefix on reconnect and keeps its fingerprint and links valid. The folder suffix is a display abbreviation. Server names allow ASCII letters, digits and hyphens.

## Install on Windows

Run **BijouShare.Server-2.0.11-win-x64-Setup.exe** on the computer hosting the shares and **BijouShare.Client-2.0.11-win-x64-Setup.exe** on each client. Both installers request administrator elevation, start the installed service immediately and configure it to start at Windows boot. You can install both on the same computer.

After an interactive installation or upgrade, click **BijouShare Server** or **BijouShare Client** in the Windows notification area to open its web UI. The icon may be under **Show hidden icons**. If setup asks for a restart, use the icon after signing in again.

The client requires the 64-bit Dokany runtime and matching driver, version 2.3 or later in the 2.x series. If either is missing or incompatible, client setup opens the [Dokany project page](https://github.com/dokan-dev/dokany) and waits. Install Dokany and choose **Retry** in BijouShare Setup. **Cancel** exits before installing BijouShare. The server uses the native Windows filesystem directly.

Both applications require a Windows version with native CNG support for ML-KEM-768 and SHA3-256. [Microsoft’s native PQC support documentation](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/libraries#post-quantum-cryptography-pqc).

## 1. Set up the server

Task Manager shows one `BijouShare.Server.exe` under **LOCAL SERVICE**. It hosts the shares and web UI even when everyone signs out. Each signed-in Windows session can also run one `BijouShare.Server.Tray.exe` under that user's account. Choosing **Exit** from the tray menu closes that session's icon and leaves the service running.

Interactive setup asks Explorer to show the server icon and checks that it appeared. If the icon is missing, open **Start > BijouShare > BijouShare Server**. Opening the shortcut again reuses the existing tray helper. The icon also starts at future sign-ins.

Click **BijouShare Server** in the Windows notification area to open [the local server UI](http://127.0.0.1:5080) in your default browser. The icon may be under **Show hidden icons**. The setup wizard requires a server name, administrator name, password of at least 14 characters, and password confirmation. Every field starts empty; no default values or credentials are supplied. Server names must contain 1–100 ASCII letters, digits, or hyphens. Setup is restricted to this computer and can initialize the server only once. The encrypted file listener becomes available after setup succeeds. Sign in to administer the server afterward.

`--init-admin` starts the same tray and setup flow. On an initialized server, the icon opens the administrator sign-in page. Change the administrator password in **Settings** after signing in. Pass `--no-browser` to either application for headless diagnostics.

Open [the administration UI](http://127.0.0.1:5080) **on the server**. Create groups, shares, and group permission rules. A share can point to a file (`D:\Reports\summary.pdf`), a folder (`D:\Team`), or a drive (`D:\`). Shares appear inside that server's client folder, for example `N:\DarkArchives_838cff90d76c4ed0\Team`. The administrator login controls this UI; there are no application-user accounts for file access.

The file protocol listens on TCP **7443** by default. The administration UI listens only on loopback HTTP **5080** by default. The file port carries the encrypted BijouShare protocol, not HTTPS or SMB. Allow incoming TCP 7443 from your LAN on the server as appropriate for your network; the application and installer do not alter firewall rules.

Server settings are in `appsettings.json`:

```json
{
  "Urls": "http://127.0.0.1:5080",
  "Server": { "ListenAddress": "0.0.0.0", "Port": 7443, "MaxConnections": 128 }
}
```

For remote web administration, configure an HTTPS Kestrel endpoint with a trusted certificate using [ASP.NET Core endpoint configuration](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/endpoints). Remote plain HTTP administration is refused. Do not configure TLS on file port 7443: its application protocol already encrypts and authenticates traffic independently.

## 2. Set up and manage a client

The installed service starts a client worker and tray icon for each signed-in Windows user. Each icon opens that account’s private management page.

Click **BijouShare Client** in the Windows notification area to open your account’s private management page. Each click uses the current session’s management address and credentials. You can close the browser and keep using your drives. First-run setup asks only for a device name. You can leave the client with no drives. Select **Add drive** in the sidebar and choose a letter when you want a drive to appear in File Explorer. Configured drives stay mounted when their servers are offline.

Use **Connect a server** on the drive tab and paste a connection or invite link from the administrator. Connections are added without remounting the drive. Without an invitation, an unknown device appears on the server under **Devices → Awaiting approval**; an administrator approves it and selects groups. Once authenticated, its server folder appears in the shared drive. Removing the last server leaves an empty mounted drive.

Select a drive's sidebar tab before adding a server. Each tab shows that drive’s server folders, approval status and server fingerprints. Renaming a device preserves both of its identity keys and its device ID. Each account manages its own connections through its client tray icon.

After sleep or a network change, the client checks its saved servers again. A healthy session can keep its open files. When a session or the Dokany mount has been lost, wait for the server folder to return and reopen the file. If a write was interrupted, check the destination before retrying it. BijouShare cannot know whether the server completed a write whose acknowledgement was lost.

### Connection links and invitations

Interactive startup registers `wad://` links for the current Windows user. The service installer also registers the handler for the machine. Links copied from the server web UI include the required fingerprint in the path and an optional invite code after `#`. Deliver the entire link through a trusted channel because it establishes which server the client will trust. The following links illustrate the format.

```powershell
wad://192.168.1.10:7443/<64-hex-server-fingerprint>
wad://192.168.1.10:7443/<64-hex-server-fingerprint>#<invite-code>
```

Windows passes the full URI to a short-lived protocol handler, so Windows process-creation auditing can record the original invite. The handler starts the client with an empty command line if needed and delivers the link through a private named pipe restricted to this Windows account. It exits after the client acknowledges the saved link. Opening a link to an already connected server preserves open files. If there are no drives, queued links survive a client restart and connect when you explicitly add your first drive. Use bracketed IPv6 addresses, for example `wad://[::1]:7443/<64-hex-server-fingerprint>`. Re-register an installed handler with `BijouShare.Client.exe --register-protocol` if the executable is moved.

The server's **Invites** page creates multiple independent codes with selected groups, a use limit or **Unlimited**, and an expiration or **Never**. The code and shareable link are shown once; store them when creating the invite. The server stores only the code hash. A valid invite automatically approves a device after private-key proof and assigns precisely those groups. Enrollment and use consumption are atomic; reconnecting an already approved device does not consume a use or change its groups. Expired, exhausted, and revoked codes cannot approve new devices. Invitations cannot override an administrator's rejection or device block. Revoking an invite prevents new enrollments; devices already enrolled retain their assigned groups until edited or blocked.

Invite codes are bearer credentials sent inside the AES-GCM connection. Pending client codes use current-user DPAPI on disk and are cleared after successful authentication.

Before enrollment, the client hashes the server’s two public keys, compares the result with the fingerprint in the link, and checks proof of possession of the corresponding private keys. A mismatch stops the connection before the client submits its proof or sends an invite. The client checks the same fingerprint on subsequent connections.

Once approved, the device can read and write according to its server group permissions. A connection link without an invite queues a new device for administrator approval. A valid invite grants the preconfigured groups.

Rejected requests remain **Blocked** until explicitly approved. Blocking an already-approved device retains its identity and server key, so enabling it again requires no enrollment exchange. Changes to device groups apply to existing file sessions. The server approves each Windows user’s client identity separately and applies the groups assigned to that identity.

### Drive letters and server placement

Add more servers in the management UI or open another `wad://` link. Servers on all of your drives use your account’s device identity. External links target your primary drive. To connect on another drive, open its sidebar tab and paste the link. Command-line configuration and `--probe` remain available for diagnostics and automation:

```powershell
.\BijouShare.Client.exe --server 192.168.1.20 --port 7443 --server-id $trustedServerFingerprint --probe
.\BijouShare.Client.exe
```

The resulting layout is `N:\DarkArchives_838cff90d76c4ed0\Team`, `N:\Media_73be70cb6df84275\Movies`, and so on. Names and full hash IDs come from the authenticated server; local IP addresses and client aliases cannot override folder names. Each server independently approves the same device identity, assigns its groups, and has its own fingerprint. Two signed-in accounts can both use N: and see different servers. A pending, blocked, or offline server does not prevent an approved server from working. When a connection/retry fails, its server folder is temporarily hidden from the drive root. Saved endpoints, identities, and pins stay in the client management UI. Background probes retry every 15 seconds and restore the same folder after authentication succeeds, without remounting the shared drive. A cached server also stays hidden at startup until it reconnects. A collision in the shortened displayed suffix fails closed when the full identities differ, including remembered offline identities.

Cross-server copies use the normal read/write permissions of the respective servers. A rename between server roots returns a cross-device error; applications can move such files by copying and then deleting when permitted.

## Service management and updates

The installers deploy to `%ProgramFiles%\BijouShare\Server` and `%ProgramFiles%\BijouShare\Client`. **BijouShare.Server** runs as **LOCAL SERVICE**. Grant that account the NTFS permissions it needs for each exported location. **BijouShare.Client** runs as **LocalSystem** and starts the drive worker with each signed-in user’s Windows token. Both services use automatic startup and restart on failure. Use **Services** to stop or restart them.

Run the newer setup executable to upgrade an installer-managed service. Use **Settings → Apps → Installed apps** to uninstall either role independently. Server identities, configuration and per-user client profiles survive uninstall. The setup executables also support `/repair`, `/uninstall`, `/passive` and `/quiet`. An unattended client install fails with exit code 1603 when Dokany is missing. Install Dokany before running setup unattended.

### Unattended installation

Run setup from an elevated PowerShell session or a deployment agent running as SYSTEM. Use `/quiet` (alias `/qn`) for silent operation or `/passive` for progress without prompts. The same switches work for a fresh install, an upgrade, `/repair`, or `/uninstall`. Setup always suppresses automatic restarts and accepts `/norestart` explicitly.

```powershell
$setup = '.\BijouShare.Server-2.0.11-win-x64-Setup.exe'
$result = Start-Process -FilePath $setup -ArgumentList '/quiet', '/norestart' -Wait -PassThru
$result.ExitCode
```

For a client, use `BijouShare.Client-2.0.11-win-x64-Setup.exe` after deploying Dokany. For an unattended repair or removal, add `/repair` or `/uninstall` to the argument list. Exit code `0` means success, `3010` means success with a restart required, and `1603` means installation failed. Unattended setup starts the installed service and skips the completion message. Users can open the web UI from the tray after sign-in.

**Moving from a script-installed service.** Setup detects an existing unmanaged service with the same name. Before switching, record its executable path and any custom server data directory in **Services**. Stop the old service and remove its service registration from elevated PowerShell with `sc.exe delete BijouShare.Server` or `sc.exe delete BijouShare.Client`, as appropriate. Keep your configuration and data directories. If the old server used a custom data directory, set `Server:DataDirectory` to that path in the installed server’s `appsettings.json` and restart the service before configuring the web UI.

## Build the installers

Use Windows x64, 64-bit PowerShell 7.4 or later, the .NET 10 SDK, and the Windows .NET Framework 4.x compiler. From the repository root, run:

```powershell
.\Installer\Build.ps1
```

The build restores pinned WiX tools, publishes both self-contained services, and verifies both setup executables before writing them and their SHA3-256 checksums to `artifacts\bijoushare\installers`. Building requires no service installation. To build just the applications, run `dotnet build BijouShare.slnx -c Release`.

## Access rules

**Only groups receive permissions.** Open **Groups** and select a group to manage its share permissions. Each ordinary group can have one permission entry per share. To set different access for a folder or file, add a path inside that entry. Each path has its own allow flags, deny flags, and inheritance setting. Use **Rename** beside a group name and press Enter to save or Escape to cancel.

Every server has a permanent **Administrator** device group. Devices assigned to it receive full file access on current and future enabled shares. Explicit denies from another group still take precedence. In **Devices**, select a device name to expand its settings. Use the scrollable group checklist to assign memberships during approval or change them later. For long lists, **Filter groups** finds groups by name and keeps selections made under earlier searches. The server rejects invitations that include Administrator, as well as attempts to rename or delete the group. The administration web UI uses its own sign-in.

Available permissions: list directories, read data, write data, create files, create directories, delete, rename/move, read attributes, write attributes/timestamps, and read permissions. `FullControl` combines those ten functions; it does not grant administration UI access or permission-policy editing from a client.

- An empty rule path targets a share root. Paths such as `Finance/2026/report.xlsx` target an individual file or folder.
- Inherited rules cover descendants. Non-inherited rules cover their exact path only.
- Grants from all memberships combine; matching explicit deny flags override grants across all memberships.
- Listing requires `ListDirectory`; visible entries require `ReadAttributes`. A typical read-only group needs `ListDirectory`, `ReadData`, `ReadAttributes`, and `ReadPermissions`.
- The server checks the authenticated device, current group memberships, and permissions on **every RPC**, including reads/writes through existing handles. Revoked handles are reclaimed. Blocking a device or changing its group permissions affects already-open handles. Revocation does not recall bytes an application already read into its own memory.
- Rules are attached to **paths**. Renames do not relocate rules. Moves that would loosen any group's access or bypass an explicit denial are rejected; adjust the policy in the server UI first.
- Share roots are fixed mount entries. Rename/delete shares through the server UI; clients cannot remove or rename a share root. Cross-share moves use copy/delete in the calling application.
- Client security descriptors are a read-only projection of the device's effective access. Windows ACL editing is denied; server rules remain the source of truth.

## File concurrency and reconnection

Explorer can inspect a folder’s attributes while another application renames it. If Explorer reports **Folder In Use**, check **Activity** on the server for a **SharingViolation** at the time of the rename. The failed open can be on the parent directory. For a conflicting BijouShare handle, the detail identifies the device, path, and share flags. A separate message identifies a conflict reported by Windows on the server’s backing storage.

Client 2.0.4 fixes a parent directory handle that could stay open after Dokany retried a denied child open. Stop the client on the affected device before replacing its binaries, then restart it. Ending the old connection releases its outstanding handles.

Multiple clients/readers can keep the same file open. At most **one writable handle per physical file** is allowed, retained until its final Windows close/disconnect, including outstanding mapped I/O. Requested Windows `FILE_SHARE_READ/WRITE/DELETE` flags are also honored, so an application can request stricter sharing. A reader must allow shared writing to coexist with a writer. Metadata changes, truncation, deletes, renames, and byte-range locks are coordinated by the server. Locks apply to clients of this service; they do not arbitrate unrelated local programs accessing the same storage. Native open sharing additionally excludes external writers while a remote writable handle is open.

Reads/writes are chunked; directory results are paginated. There is no offline cache. A heartbeat reconnects the client after network loss. Existing remote handles become invalid after reconnection, and applications must reopen their files. Writes are never automatically retried after an uncertain network outcome. Disconnected server sessions are reclaimed after a 90-second idle timeout; application-level heartbeat traffic normally runs every 15 seconds.

A request canceled while still waiting to transmit reports an IO timeout and leaves unrelated in-flight requests on their existing session. Once a request may have been sent, a timeout/failure closes that session to avoid ambiguous replies or replaying writes.

## Performance and upgrading

BijouShare releases the client and server together under the version in `Directory.Build.props`. Deploy the matching server and client packages for each update, including releases that fix only one component.

Version 2.0 requires protocol v6 and fresh server and client configurations. When replacing an earlier installation, stop both apps and retain the old state directories separately. Start setup with empty data directories, configure the groups and shares, and distribute new links from the server. The apps reject earlier state files without rewriting them.

Modern peers negotiate raw binary file payloads inside AES-256-GCM frames, eliminating JSON Base64 expansion. Transfers use chunks up to 1 MiB and a bounded window of 16 requests per connection. Reads can execute concurrently; mutations retain request order and coordinate with earlier reads. Server IO permits concurrent readers across connections while retaining the single-writer rule. Buffer pooling reduces large allocations, and directory pagination keeps a bounded enumeration cursor instead of repeatedly scanning preceding entries. Current authorization is checked for every request; cached permissions and directory cursors are invalidated when server configuration changes.

P-256 ECDH and ML-KEM-768 run during connection setup. File contents and operation metadata use symmetric AES-256-GCM for both the binary transfer mode and the diagnostic JSON mode.

Run an isolated encrypted TCP benchmark on the server machine with:

```powershell
.\BijouShare.Server.exe --benchmark --benchmark-output performance.json
```

It generates test files under `artifacts\benchmarks` in the working directory, verifies sequential/concurrent transfer hashes, and records throughput, allocations, small reads, and directory listing time. Results use loopback TCP and a warm OS file cache; they are not a measurement of a remote client's LAN or physical disk throughput.

## Keys, state, and scope

Server state defaults to `%ProgramData%\BijouShare\Server`. Each Windows user's client state lives in `%USERPROFILE%\.bijoushare`, independently of the executable location. Its `client.json` contains both identity public keys, the current-user DPAPI-protected P-256 private key and ML-KEM private seed, the full device ID, and the user's drive and server settings. The client checks that each private key matches its public key and that the pair matches the saved device ID. The profile also contains `web-keys\` and the instance lock.

Client startup restricts the profile directory and its existing files, including client.json, backups and web keys, to the owning Windows account and SYSTEM. New files inherit these permissions. The server excludes client profiles even when an enclosing directory or drive is shared. Local Windows administrators can take ownership using operating system privileges.

Client private keys and pending invite secrets use current-user DPAPI. Server private keys use machine-bound DPAPI. Both use restricted directory ACLs. Each server has one persistent ECDH and ML-KEM identity for all clients. A replacement machine needs its own setup, connection links and device approvals. Administrator password hashes use PBKDF2-HMAC-SHA3-256 with random salt and 600,000 iterations. Configuration updates are atomic; audit events append to daily JSONL files under the server data directory's `audit` folder. Frequent open/write audit records use a bounded queue and a 250 ms flush interval, drained on graceful shutdown; an abrupt process or machine failure can lose the unflushed tail. Authentication, administration, and other audit records flush synchronously. Recent activity is reloaded after restart from bounded tails of the latest audit files; the UI shows up to 200 recent events. Archive/rotate old daily files according to your retention needs.

**Fingerprints.** Each Windows client profile and each server has a persistent P-256 ECDH key pair and a persistent ML-KEM-768 key pair. Both use the same ID formula. Concatenate the canonical DER SubjectPublicKeyInfo bytes for the ECDH public key with the raw ML-KEM encapsulation key bytes, hash once with SHA3-256, and encode the result as 64 lowercase hexadecimal characters. Display names, addresses and drive letters are independent of the ID. Change the server display name under **Settings** or the client name under **Device settings**.

**Handshake and transfers.** Both peers contribute fresh ephemeral key material and random nonces and prove possession of their persistent keys. The ECDH contribution hashes the static and ephemeral raw agreements together. The ML-KEM contribution hashes the secrets encapsulated to the client identity, server identity and ephemeral client key, in that order. The hybrid secret is `SHA3-256(ECDH contribution || ML-KEM contribution)`.

Key confirmation and traffic keys use separate purpose labels bound to the handshake transcript. Each direction has its own AES-256-GCM key and nonce prefix and advances its frame counter. This separates traffic in both directions and across reconnects, including sessions opened in the same second. The one-step SHA3 key expansion follows the counter, shared-secret and context layout in [NIST SP 800-56C Rev. 2, section 4.1](https://doi.org/10.6028/NIST.SP.800-56Cr2).

The exported namespace supports ordinary Windows file/folder I/O, memory-mapped I/O, attributes, timestamps, sizing, enumeration, rename, deletion, and locking. Native write-through requests are honored, and paging writes cannot extend EOF. NTFS-specific features such as alternate data streams, reparse points/symlinks/junctions, hard-link creation, sparse controls, EFS, compression controls, and client-side ACL modification are not exposed. Unsupported EFS creation requests fail instead of silently creating an unencrypted file. Reparse paths, traversal, device names, and alternate-stream syntax are rejected. Windows short-name aliases are expanded before permission/confinement checks. The server's data directory, default `%ProgramData%\BijouShare` tree, and executable directory are excluded even when sharing an entire drive. Local storage administrators and the service host remain trusted; do not let untrusted local processes replace share path components with reparse points during file operations.

## Validation

If Explorer cannot open the drive letter, check that drive’s mount status in the client web UI for the signed-in Windows account. The client periodically opens the virtual root and remounts the drive after repeated failures. A configured drive should open even with zero connected servers.

If the mounted drive is empty, check the server connection status in the drive’s tab. If a server folder opens but has no shares, check device membership and the enabled shares in the server UI. For ordinary groups, leave the relative path empty to grant access to a share root. The read-only preset includes the root permissions Explorer uses to list it. An exported drive root remains visible even when Windows marks its physical root Hidden or System. Entries below the root retain their Windows attributes.

If creating a folder inside a share fails, open **Activity** on the server and find the denied **Open** for that path. The detail identifies a missing BijouShare group permission or a Windows storage denial when that check fails. For a Windows denial, find the account shown under **Shares** and check its NTFS permissions on the physical parent folder. Folder creation needs **Create folders / append data**. Use **Modify** on the intended subtree if that account also needs to edit, rename, and delete files.

Run the built-in checks from each published service directory.

```powershell
.\BijouShare.Server.exe --self-test
.\BijouShare.Client.exe --self-test
```

The server tests cover group permissions and live revocation, single-writer sharing, path confinement, encrypted TCP authentication and request ordering. The client tests cover per-user profiles, invite parsing, fingerprint checks, server routing and reconnects. Shared tests exercise native ML-KEM, known SHA3 fingerprint and key derivation vectors, role-specific key confirmation, AES-GCM tamper detection and replay rejection.

Before a release, check dependency advisories with:

```powershell
dotnet list BijouShare.slnx package --vulnerable --include-transitive --no-restore
```

Implementation references: [DokanNet callback contract](https://github.com/dokan-dev/dokan-dotnet/blob/master/DokanNet/IDokanOperations.cs), [official mount example](https://github.com/dokan-dev/dokan-dotnet/blob/master/sample/DokanNetMirror/Program.cs), and [Microsoft Windows service hosting](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service).
