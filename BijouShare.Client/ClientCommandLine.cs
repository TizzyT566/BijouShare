namespace BijouShare.Client;

internal enum ClientCommand
{
    Run,
    OpenManagement,
    Help,
    SelfTest,
    Probe
}

internal sealed class ClientCommandLine
{
    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);
    public ClientCommand Command
    {
        get; private set;
    }
    public WadUri? Link
    {
        get; private set;
    }
    public bool RegisterProtocol
    {
        get; private set;
    }
    public bool NoBrowser
    {
        get; private set;
    }
    public bool SessionWorker { get; private set; }
    public string? this[string option] => values.GetValueOrDefault(option);

    public static ClientCommandLine Parse(string[] args)
    {
        var result = new ClientCommandLine();
        var commands = new List<ClientCommand>();
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case var link when link.StartsWith("wad:", StringComparison.OrdinalIgnoreCase):
                    if (result.Link is not null)
                        throw new ArgumentException("Open only one wad link at a time.");
                    result.Link = WadUri.Parse(link);
                    break;
                case "--register-protocol":
                    result.RegisterProtocol = true;
                    break;
                case "--no-browser":
                    result.NoBrowser = true;
                    break;
                case "--session-worker":
                    result.SessionWorker = true;
                    break;
                case "--open-management":
                    commands.Add(ClientCommand.OpenManagement);
                    break;
                case "--help" or "-h" or "/?":
                    commands.Add(ClientCommand.Help);
                    break;
                case "--self-test":
                    commands.Add(ClientCommand.SelfTest);
                    break;
                case "--probe":
                    commands.Add(ClientCommand.Probe);
                    break;
                case "--data-dir" or "--name" or "--mount" or "--server" or "--port" or "--server-id" or "--server-name" or "--management-port":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]) ||
                        args[index + 1].StartsWith("--", StringComparison.Ordinal) || args[index + 1] is "-h" or "/?")
                        throw new ArgumentException($"{argument} requires a value. Use --help for examples.");
                    if (!result.values.TryAdd(argument, args[++index]))
                        throw new ArgumentException($"{argument} can be specified only once.");
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {argument}. Use --help for available options.");
            }
        }

        if (commands.Count > 1)
            throw new ArgumentException("Choose one command: --open-management, --probe, --self-test, or --help.");
        result.Command = commands.Count == 0 ? ClientCommand.Run : commands[0];
        if (result.Command == ClientCommand.OpenManagement && args.Length != 1)
            throw new ArgumentException("Use --open-management by itself to open this Windows user's client console.");
        if (result.Command is ClientCommand.Help or ClientCommand.SelfTest && result.values.Count != 0)
            throw new ArgumentException("Setup options cannot be combined with --help or --self-test.");
        if (result["--port"] is not null && result["--server"] is null)
            throw new ArgumentException("Use --port with --server.");
        if (result["--server-id"] is { } fingerprint)
        {
            if (result["--server"] is null || result.Command is not (ClientCommand.Run or ClientCommand.Probe))
                throw new ArgumentException("Use --server-id with --server when running or probing the client.");
            BijouShare.Shared.ServerIdentityNaming.ValidateId(fingerprint);
        }
        if (result.Link is not null && (result["--server"] is not null || result.Command is not (ClientCommand.Run or ClientCommand.Probe)))
            throw new ArgumentException("A wad link can be used when running or probing, without --server.");
        if (result.RegisterProtocol && result.Command is not ClientCommand.Run)
            throw new ArgumentException("--register-protocol cannot be combined with another command.");
        if (result["--server-name"] is not null)
            throw new ArgumentException("Change the server name in the server's Settings page. Client folder names use the authenticated server name and fingerprint.");
        return result;
    }

    public const string Help = """
        BijouShare Client — Windows virtual drive service

        Run without arguments, then click BijouShare Client in the Windows notification area
        to open device setup or manage your drives.
        Setup saves your device name. Use Add drive when you are ready to mount a drive.

          wad://HOST:PORT/SERVER-FINGERPRINT[#INVITE-CODE]
              Add a server to the running client, or start the client if needed.
              Invitation codes can automatically enroll the device with predefined groups.
          --register-protocol
              Register this executable to open wad links for the current Windows user.
          --open-management
              Open the signed-in user's running client console once in the default browser.
          --management-port 5081
              Use a fixed loopback port. By default Windows chooses an available port.
          --no-browser
              Run without a tray icon or wad link registration (for diagnostics).

          --server HOST [--port 7443] [--name DEVICE] [--mount N:\]
              Create/reuse this device identity, add/update a server, and connect.
              The primary drive contains folders such as N:\ServerName_First16IdCharacters\Share.
              Each server supplies its current display name when the client connects.
              Unknown devices wait for administrator approval in the server's Devices page.
              Approved servers appear under the shared drive; subsequent starts reuse this configuration.
          --probe [--server HOST] [--port 7443]
              Report approval status and authorized shares for every configured server without mounting.
          --server-id FULL-FINGERPRINT
              Required when adding a new host. Supply the 64-character lowercase fingerprint from the server.
              Later connections to a saved endpoint reuse its fingerprint.
          --self-test
              Run protocol, configuration, and client callback regression checks.
          Profile files, including client.json and web-keys, live in %USERPROFILE%\.bijoushare.
          --mount N:\
              Select this drive for the server, adding the letter if needed.
          --name "Laptop name"
              Save this profile's display name (1-100 characters; defaults to your Windows user name).
              Names may contain spaces, but no surrounding whitespace or control characters.
              The chosen name updates on each server on the next authenticated connection,
              including pending requests. Device identity and group assignments are retained.
          --help
              Show this help without creating files or connecting to the server.

        Install Dokany 2.3.x before mounting. Approve pending devices and assign groups on the server.
        The client verifies the pinned identity before sending an invite. Server group rules govern share access.
        """;
}
