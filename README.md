# BijouShare

A C#/.NET 10 Windows solution containing exactly **two executable projects**:

| Project | Role |
| --- | --- |
| `BijouShare.Server` | Windows service, encrypted LAN file server, device approval, groups/shares/rules, and an ASP.NET Core administration UI. |
| `BijouShare.Client` | Windows service that registers its persistent device identity automatically and mounts all configured servers under one Dokany drive, with a root folder for each server. |

`Shared/` contains linked source compiled into both projects. It is not another project. Both services can also run in a console for setup and troubleshooting. Version 0.4 replaces enrollment-file exchange and application users with automatic device requests, administrator approval, and device group memberships. It retains the optimized binary/AES-GCM transport and whole-drive visibility fix.

Version 0.5 names server folders using `ServerName_<first16hex>`, where the full ID is SHA-256 of the UTF-8 server name followed by its canonical SPKI public-key bytes. The full public key remains the client's pinned authentication anchor; the shortened suffix is for display. Server names allow only ASCII letters, digits, and hyphens.

## Prerequisites and build

- Windows x64 and the .NET 10 SDK or newer for building.
- Windows CNG with native ML-KEM support on **both** machines. The runtime checks `MLKem.IsSupported`; unsupported systems report the requirement and cannot fall back to ECDH alone. No external native DLL or managed ML-KEM implementation is bundled. See [Microsoft's native PQC support documentation](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/libraries#post-quantum-cryptography-pqc).
- PowerShell 7.3 or newer for the helper scripts, including service installation.
- [Dokany 2.3.x](https://github.com/dokan-dev/dokany/releases) installed on **client machines**. The project uses [DokanNet 2.3.0.3](https://www.nuget.org/packages/DokanNet). The server accesses its own local files directly; it does not require the Dokany driver.
- A free client drive letter, such as `N:`.

```powershell
dotnet restore BijouShare.slnx
dotnet build BijouShare.slnx -c Release
.\scripts\Publish.ps1
```

The publish script creates self-contained Windows x64 distributions under `artifacts\bijoushare\publish\Server` and `artifacts\bijoushare\publish\Client`, along with a build manifest, this guide, and a standalone installer script. Keep each entire service directory together, including server `wwwroot` and configuration files. Use `--help` on either executable to inspect setup commands without creating state or connecting to the server.

## 1. Initialize and start the server

Run the server from elevated PowerShell with no setup arguments:

```powershell
cd artifacts\bijoushare\publish\Server
.\BijouShare.Server.exe
```

On first run, the browser opens [the local server UI](http://127.0.0.1:5080). Its setup wizard requires a server name, administrator name, password of at least 14 characters, and password confirmation. Every field starts empty; no default values or credentials are supplied. Server names must contain 1–100 ASCII letters, digits, or hyphens. Setup is restricted to this computer and can initialize the server only once. The encrypted file listener becomes available after setup succeeds. Sign in to administer the server afterward.

`--init-admin` opens the same web setup/sign-in flow; it does not reset an existing administrator. Change an existing administrator password through Settings after signing in. Existing configured servers keep their identity, credentials, groups, and permissions and display the normal sign-in page. Windows services expose the same web UI without launching a browser; `--no-browser` also suppresses browser launch for diagnostics.

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

On each client, run elevated:

```powershell
.\BijouShare.Client.exe
```

The client opens its management UI at [http://127.0.0.1:5081](http://127.0.0.1:5081). First-run setup asks for the device name and one unused shared drive letter. After saving, the drive mounts immediately and stays mounted while the client runs, including when it contains no servers or all servers are pending/offline. Existing configurations are reused automatically. No setup arguments are required.

Use **Add server** in the client UI to enter a hostname/port, paste a connection link, or supply an invitation. Connections are added without remounting the drive. Without an invitation, an unknown device appears on the server under **Devices → Awaiting approval**; an administrator approves it and selects groups. Once authenticated, its server folder appears in the shared drive. Removing the last server leaves an empty mounted drive.

The client UI shows connection/approval status, server identity fingerprints, and each mounted folder. Device name changes reconnect servers with the saved identity; groups and keys stay intact. Drive-letter changes are saved for the next client restart and the UI shows when a restart is needed. Names may contain spaces and must be 1-100 characters without surrounding whitespace or control characters. Management is restricted to this computer, with loopback/Host/Origin checks and CSRF protection. Local applications share this machine-wide device identity.

### Connection links and invitations

Interactive startup registers `wad://` links for the current Windows user. The service installer also registers the handler for the machine. Webpages can link to either form:

```powershell
wad://192.168.1.10:7443
wad://192.168.1.10:7443/INVITE_CODE
```

Links forward to the running client through a local activation channel; they do not start a second drive instance. If setup is unfinished, the link waits for the web setup to finish. Use bracketed IPv6 addresses, for example `wad://[::1]:7443`. Re-register an installed handler with `BijouShare.Client.exe --register-protocol` if the executable is moved.

The server's **Invites** page creates multiple independent codes with selected groups, a use limit or **Unlimited**, and an expiration or **Never**. The code and shareable link are shown once; store them when creating the invite. The server stores only the code hash. A valid invite automatically approves a device after private-key proof and assigns precisely those groups. Enrollment and use consumption are atomic; reconnecting an already approved device does not consume a use or change its groups. Expired, exhausted, and revoked codes cannot approve new devices. Invitations cannot override an administrator's rejection or device block. Revoking an invite prevents new enrollments; devices already enrolled retain their assigned groups until edited or blocked.

Invite codes are bearer credentials and travel only inside the mutually authenticated AES-GCM connection. Pending client codes are DPAPI-protected on disk and cleared after successful authentication. The client UI never returns private keys or invite credentials in its state API.

Use `--data-dir <absolute-directory>` for custom state. Reusing that state reuses the identity. The first approved connection pins the server's complete public identity key automatically; subsequent connections require that same key and proof of its private-key possession. This first-contact trust assumes the configured LAN endpoint is the intended server. The UI and client expose fingerprints if independent verification is needed. An existing pin is never silently replaced; `--reset-server-trust` is an explicit recovery action for an intentional server identity replacement.

Rejected requests remain **Blocked** until explicitly approved. Blocking an already-approved device retains its identity and server key, so enabling it again requires no enrollment exchange. Changes to device groups apply to existing file sessions. The virtual drive is machine-wide when run as a service: local applications share that device's group permissions. Individual interactive Windows accounts are not file-access principals.

### Multiple servers, one drive

Add more servers in the management UI or open another `wad://` link. All use the same client identity and drive letter. Command-line configuration and `--probe` remain available for diagnostics and automation:

```powershell
.\BijouShare.Client.exe --server 192.168.1.20 --port 7443 --probe
.\BijouShare.Client.exe
```

The resulting layout is `N:\DarkArchives_838cff90d76c4ed0\Team`, `N:\Media_73be70cb6df84275\Movies`, and so on. Names and full hash IDs come from the authenticated server; local IP addresses and client aliases cannot override folder names. Each server independently approves the same device identity, assigns its groups, and has its own pinned server key. There is one configured mount letter for the entire client. A pending, blocked, or offline server does not prevent an approved server from working. When a connection/retry fails, its server folder is temporarily hidden from the drive root. Saved endpoints, identities, and pins stay in the client management UI. Background probes retry every 15 seconds and restore the same folder after authentication succeeds, without remounting the shared drive. A cached server also stays hidden at startup until it reconnects. A collision in the shortened displayed suffix fails closed when the full identities differ, including remembered offline identities.

Cross-server copies use the normal read/write permissions of the respective servers. A rename between server roots returns a cross-device error; applications can move such files by copying and then deleting when permitted.

## 3. Install the Windows services

Deploy the full service directories to a protected installation location, such as the following paths, and stop console instances. Run the installer elevated after server administrator initialization and client web setup. A client with no servers can be installed; it starts with an empty drive:

```powershell
.\scripts\Install-Service.ps1 -Role Server -PublishDirectory 'C:\Program Files\BijouShare\Server' -WhatIf
.\scripts\Install-Service.ps1 -Role Server -PublishDirectory 'C:\Program Files\BijouShare\Server' -Start
.\scripts\Install-Service.ps1 -Role Client -PublishDirectory 'C:\Program Files\BijouShare\Client' -Start
```

Use the actual deployed directories. The installer does not copy files: it verifies initialization, refuses unsafe reparse paths or writable ancestor directories, protects the published tree, and registers the executable with a quoted absolute path. `-WhatIf` previews the action without installing a service or changing ACLs. Pass `-DataDirectory` when using custom state. Partial service registration is rolled back if configuration/startup fails.

Install the server on its server machine and the client on each client machine; both can coexist for local testing. The server runs as **LOCAL SERVICE**; the client runs as **LocalSystem**, which is needed for the machine-wide driver mount. Grant LOCAL SERVICE the underlying NTFS rights required for the exported files/folders. Application group permissions are always limited by the server service account's actual filesystem access. The installer leaves firewall rules unchanged.

Service names are `BijouShare.Server` and `BijouShare.Client`. The installer configures automatic startup and restart on failure. Manage them with `Start-Service`, `Stop-Service`, and the Windows Services console. For updates, stop the service, replace its published files, and start it again. Install Dokany separately before starting a client service.

## Access rules

Devices contain their identity, enabled status, and group memberships. **Only groups receive permissions.** Rules reference a group, share, relative path, allow flags, deny flags, and inheritance setting. New devices/groups/shares have no access until matching group rules grant it. Application users and direct device-permission assignments do not exist.

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

Multiple clients/readers can keep the same file open. At most **one writable handle per physical file** is allowed, retained until its final Windows close/disconnect, including outstanding mapped I/O. Requested Windows `FILE_SHARE_READ/WRITE/DELETE` flags are also honored, so an application can request stricter sharing. A reader must allow shared writing to coexist with a writer. Metadata changes, truncation, deletes, renames, and byte-range locks are coordinated by the server. Locks apply to clients of this service; they do not arbitrate unrelated local programs accessing the same storage. Native open sharing additionally excludes external writers while a remote writable handle is open.

Reads/writes are chunked; directory results are paginated. There is no offline cache. A heartbeat reconnects the client after network loss. Existing remote handles become invalid after reconnection, and applications must reopen their files. Writes are never automatically retried after an uncertain network outcome. Disconnected server sessions are reclaimed after a 90-second idle timeout; application-level heartbeat traffic normally runs every 15 seconds.

A request canceled while still waiting to transmit reports an IO timeout and leaves unrelated in-flight requests on their existing session. Once a request may have been sent, a timeout/failure closes that session to avoid ambiguous replies or replaying writes.

## Performance and upgrading

Version **0.8 requires both endpoints to be updated together**. Protocol v3 requires `P256-MLKEM768-HKDFSHA256-AES256GCM`; previous classical-only protocols and missing/altered hybrid fields are rejected. There is no compatibility switch or automatic downgrade. Existing device IDs, persistent identity keys, server IDs, pins, groups, shares, and permissions remain valid; no enrollment reset or state migration is needed.

Version 0.4 introduced automatic approval. Stop each process/service, replace its published files, and restart it while preserving configuration and `%ProgramData%` state. Existing approved device keys/pins remain valid. On first server startup, legacy users are removed and each device receives its former user's groups. A device stays enabled only if both it and its former user were enabled. The exact legacy state is backed up inside the protected server data directory as `state.json.before-device-groups-<id>.bak` before schema migration. Rolling back to a pre-0.4 server requires restoring that private state backup along with the old binaries. Current clients and servers must both use protocol v3.

Version 0.5 introduced authenticated server folder names. Existing server state gains a persistent global P-256 identity key and a name derived from a sanitized machine name; a protected exact backup is created as `state.json.before-server-identity-<id>.bak`. Groups, devices, their key pairs, permission rules, pending decisions, and administrator credentials are preserved. The active schema version is 3. Updated clients require the server's authenticated identity metadata and hybrid protocol; they never invent an IP-based folder for an incompatible endpoint.

Version 0.6 adds browser-based client setup/management, persistent empty drive mounting, `wad://` activation, and server invitations. Both endpoints need 0.6 or later to redeem invitations. Version 0.7 adds browser-based server setup and temporarily hides disconnected server folders until they reconnect. Existing server/device keys, administrator credentials, permissions, pins, and drive settings are retained; no schema migration is required.

Modern peers negotiate raw binary file payloads inside AES-256-GCM frames, eliminating JSON Base64 expansion. Transfers use chunks up to 1 MiB and a bounded window of 16 requests per connection. Reads can execute concurrently; mutations retain request order and coordinate with earlier reads. Server IO permits concurrent readers across connections while retaining the single-writer rule. Buffer pooling reduces large allocations, and directory pagination keeps a bounded enumeration cursor instead of repeatedly scanning preceding entries. Current authorization is checked for every request; cached permissions and directory cursors are invalidated when server configuration changes.

The client authentication log reports `P-256 + ML-KEM-768 (Windows CNG)` for key establishment and `pipelined AES-GCM binary` for optimized transfers. ECDH and ML-KEM run only during connection setup; file contents and operation metadata continue to use symmetric AES-256-GCM. The JSON payload test mode also requires the hybrid handshake.

Run an isolated encrypted TCP benchmark on the server machine with:

```powershell
.\BijouShare.Server.exe --benchmark --benchmark-output performance.json
```

It generates test files under `artifacts\benchmarks` in the working directory, verifies sequential/concurrent transfer hashes, and records throughput, allocations, small reads, and directory listing time. Results use loopback TCP and a warm OS file cache; they are not a measurement of a remote client's LAN or physical disk throughput.

## Keys, state, and scope

Server state defaults to `%ProgramData%\BijouShare\Server`; client configuration/identity defaults to `%ProgramData%\BijouShare\Client`. Both accept `--data-dir <absolute-directory>`; use the same argument for setup and service installation when overriding the location. Use a dedicated directory, never a drive root or reparse path. Client `client.json` also contains endpoint, server pin, mount letter, and request timeout settings. The client validates its key pair, endpoint, mount point, and timeout before connecting. Stop a client before editing that file. A data directory can be held by only one running/setup instance.

Private keys use Windows machine-bound DPAPI and restricted directory ACLs. Server private keys are distinct per enrolled device. Machine-bound encrypted state is not portable to another machine: re-enroll devices after migration. Administrator passwords use PBKDF2-SHA256 with random salt and 600,000 iterations. Configuration updates are atomic; audit events append to daily JSONL files under the server data directory's `audit` folder. Frequent open/write audit records use a bounded queue and a 250 ms flush interval, drained on graceful shutdown; an abrupt process or machine failure can lose the unflushed tail. Authentication, administration, and other audit records flush synchronously. Recent activity is reloaded after restart from bounded tails of the latest audit files; the UI shows up to 200 recent events. Archive/rotate old daily files according to your retention needs.

Every connection uses fresh client/server ephemeral P-256 keys, a fresh client ML-KEM-768 key, and random challenges. The server encapsulates to that ML-KEM key using native Windows CNG. HKDF-SHA256 combines the fixed-length persistent identity ECDH secret, ephemeral ECDH secret, and ML-KEM shared secret. Separate purpose/role labels derive handshake authentication keys and 72 bytes of independent directional AES-256-GCM keys/nonce prefixes. Version, exact suite, both ephemeral public contributions, ML-KEM ciphertext, identities, approval status, and capabilities are transcript-bound. Wrong or tampered ML-KEM ciphertext yields an unrelated secret and fails proof confirmation before invitations or file operations are sent. Secrets are cleared after use; ephemeral private keys are disposed and never persisted.

**All file contents and operation metadata remain symmetrically encrypted with AES-256-GCM.** Sequence-number nonces reject frame tampering and replay. The hybrid exchange protects recorded session confidentiality against compromise of the classical ECDH component. Persistent device and server identity authentication still uses P-256; this change does not provide post-quantum signatures or protection against an active attacker who can break those long-term identity keys. Existing identity keys, pins, and server folder hashes remain unchanged.

The server-wide identity is separate from its persistent per-device ECDH keys. Its additional role-separated proof combines the global identity ECDH secret with the same ephemeral ECDH and ML-KEM contributions and binds the server name, full name/public-key hash, and session transcript. The client verifies the complete hash and full pinned public key; it never relies on the 16-character display suffix alone. A changed key, missing naming metadata, or absent hybrid contribution fails authentication.

The exported namespace supports ordinary Windows file/folder I/O, memory-mapped I/O, attributes, timestamps, sizing, enumeration, rename, deletion, and locking. Native write-through requests are honored, and paging writes cannot extend EOF. NTFS-specific features such as alternate data streams, reparse points/symlinks/junctions, hard-link creation, sparse controls, EFS, compression controls, and client-side ACL modification are not exposed. Unsupported EFS creation requests fail instead of silently creating an unencrypted file. Reparse paths, traversal, device names, and alternate-stream syntax are rejected. Windows short-name aliases are expanded before permission/confinement checks. The server's data directory, default `%ProgramData%\BijouShare` tree, and executable directory are excluded even when sharing an entire drive. Local storage administrators and the service host remain trusted; do not let untrusted local processes replace share path components with reparse points during file operations.

## Validation

If the drive has not appeared, check whether the device is awaiting approval or blocked in the server UI. If it is mounted but empty, verify that the device belongs to a group with a permission rule for the enabled share. To grant access to the share root, leave the rule's relative path empty; do not repeat the share name. The read-only preset includes the root metadata/list permissions required by Explorer. Physical Hidden/System flags on a drive root do not hide an explicitly exported virtual share; child-file attributes remain unchanged.

Tests are compiled into the existing executables, preserving the two-project solution:

```powershell
dotnet BijouShare.Server/bin/Release/net10.0-windows/BijouShare.Server.dll --self-test
dotnet BijouShare.Client/bin/Release/net10.0-windows/BijouShare.Client.dll --self-test
```

The server tests cover permissions, live revocation, single-writer sharing, handle ownership, range locks, path rejection, protected storage, rename policy, directory pagination, real encrypted TCP authentication, concurrent request correlation, and mutation ordering. Hybrid tests exercise native ML-KEM encapsulation/decapsulation, malformed inputs, implicit rejection, all-secret key derivation, transcript/role binding, downgrade refusal, and preserved pins. Protocol tests also cover symmetric encryption, tampering, replay, binary bounds, and exact short reads.

For repeatable end-to-end acceptance testing, publish first and run the following elevated:

```powershell
.\scripts\Test-Acceptance.ps1
# Optional: with Node.js, Chrome, and playwright available
.\scripts\Test-Acceptance.ps1 -WebUi
# Override occupied ports or the drive letter when needed
.\scripts\Test-Acceptance.ps1 -Drive 'R:\' -FilePort 17444 -AdminPort 15081
```

The wrapper creates isolated fixtures with test-only credentials, checks native file operations and live permission changes, and starts two servers plus a fresh client on one drive to verify automatic approval, group deny precedence, independent pins, cross-server copying, outage isolation, and block/re-enable behavior. Temporary processes stop in `finally` blocks. It refuses occupied test ports/drive letters. The mount test requires a generated acceptance-fixture marker before writing, to avoid accidentally testing a production share. Keep test-only credentials out of deployed state.

For browser QA, install `playwright` in your development environment, or set `PLAYWRIGHT_MODULE` to an existing package path. Browser screenshots are saved under `artifacts\ui`; isolated fixture logs remain under `artifacts\acceptance-<id>` for troubleshooting. Test artifacts use only generated identities, state, and files.

Before a release, check dependency advisories with:

```powershell
dotnet list BijouShare.slnx package --vulnerable --include-transitive --no-restore
```

Implementation references: [DokanNet callback contract](https://github.com/dokan-dev/dokan-dotnet/blob/master/DokanNet/IDokanOperations.cs), [official mount example](https://github.com/dokan-dev/dokan-dotnet/blob/master/sample/DokanNetMirror/Program.cs), and [Microsoft Windows service hosting](https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service).

## Upgrading to BijouShare 0.9

Upgrade both the server and all clients together: the authenticated protocol name is now BijouShare. Stop previous service instances before replacing binaries. Install the services under their new BijouShare.Server and BijouShare.Client names; remove obsolete service registrations so they cannot start alongside the replacement. Re-register the wad URI handler from the new client executable using --register-protocol.

New installations default to the BijouShare folders under ProgramData. To retain an existing installation, pass --data-dir with its original absolute data directory on the same Windows computer, and use that same directory when installing the renamed service. This retains device keys, server identity, approval records, groups, permissions, invites, and client settings. Keep a backup of that directory before upgrading. The product rename requires signing in to the web UI again.
