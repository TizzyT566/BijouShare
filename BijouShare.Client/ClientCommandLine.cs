namespace BijouShare.Client;

internal enum ClientCommand
{
    Run,
    Help,
    SelfTest,
    CreateDevice,
    ImportEnrollment,
    Probe
}

internal sealed class ClientCommandLine
{
    private readonly Dictionary<string, string> values = new(StringComparer.Ordinal);
    public ClientCommand Command
    {
        get; private set;
    }
    public bool ResetServerTrust
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
                case "--help" or "-h" or "/?":
                    commands.Add(ClientCommand.Help);
                    break;
                case "--self-test":
                    commands.Add(ClientCommand.SelfTest);
                    break;
                case "--create-device":
                    commands.Add(ClientCommand.CreateDevice);
                    break;
                case "--probe":
                    commands.Add(ClientCommand.Probe);
                    break;
                case "--reset-server-trust":
                    if (result.ResetServerTrust)
                        throw new ArgumentException("--reset-server-trust can be specified only once.");
                    result.ResetServerTrust = true;
                    break;
                case "--import-enrollment" or "--data-dir" or "--name" or "--out" or "--mount" or "--server" or "--port" or "--server-name" or "--management-port":
                    if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]) ||
                        args[index + 1].StartsWith("--", StringComparison.Ordinal) || args[index + 1] is "-h" or "/?")
                        throw new ArgumentException($"{argument} requires a value. Use --help for examples.");
                    if (!result.values.TryAdd(argument, args[++index]))
                        throw new ArgumentException($"{argument} can be specified only once.");
                    if (argument == "--import-enrollment")
                        commands.Add(ClientCommand.ImportEnrollment);
                    break;
                default:
                    throw new ArgumentException($"Unknown option: {argument}. Use --help for available options.");
            }
        }

        if (commands.Count > 1)
            throw new ArgumentException("Choose one command: --create-device, --import-enrollment, --probe, --self-test, or --help.");
        result.Command = commands.Count == 0 ? ClientCommand.Run : commands[0];
        if (result.Command != ClientCommand.CreateDevice && result["--out"] is not null)
            throw new ArgumentException("--out applies only to --create-device.");
        if (result.Command is ClientCommand.Help or ClientCommand.SelfTest && result.values.Count != 0)
            throw new ArgumentException("Setup options cannot be combined with --help or --self-test.");
        if (result.Command == ClientCommand.ImportEnrollment && (result["--server"] is not null || result["--port"] is not null || result.ResetServerTrust))
            throw new ArgumentException("Importing a legacy bundle cannot be combined with automatic server configuration.");
        if (result["--port"] is not null && result["--server"] is null)
            throw new ArgumentException("Use --port with --server.");
        if (result.Link is not null && (result["--server"] is not null || result.Command is not (ClientCommand.Run or ClientCommand.Probe)))
            throw new ArgumentException("A wad link can be used when running or probing, without --server.");
        if (result.RegisterProtocol && result.Command is not ClientCommand.Run)
            throw new ArgumentException("--register-protocol cannot be combined with another command.");
        if (result["--server-name"] is not null)
            throw new ArgumentException("Server names are set on the server during --init-admin. Client folder names use that authenticated name and server ID.");
        if (result.ResetServerTrust && result.Command is not (ClientCommand.Run or ClientCommand.Probe))
            throw new ArgumentException("--reset-server-trust applies when running or probing the client.");
        return result;
    }

    public const string Help = """
        BijouShare Client — Windows virtual drive service

        Run without arguments to open first-time setup in the local management web UI.
        Once configured, the selected drive stays mounted even with no connected servers.

          wad://HOST:PORT[/INVITE-CODE]
              Add a server to the running client, or start the client if needed.
              Invitation codes can automatically enroll the device with predefined groups.
          --register-protocol
              Register this executable to open wad links for the current Windows user.
          --management-port 5081
              Set the local management web UI port (loopback only).
          --no-browser
              Start without opening a browser or registering links (for service diagnostics).

          --server HOST [--port 7443] [--name DEVICE] [--mount N:\]
              Create/reuse this device identity, add/update a server, and connect.
              All servers share one drive: N:\ServerName_First16IdCharacters\Share.
              Server names are supplied by each server during --init-admin.
              Unknown devices wait for administrator approval in the server's Devices page.
              Approved servers appear under the shared drive; subsequent starts reuse this configuration.
          --probe [--server HOST] [--port 7443]
              Report approval status and authorized shares for every configured server without mounting.
          --reset-server-trust
              Explicitly discard the selected --server pin after verifying an intentional key change.
          --self-test
              Run protocol, configuration, and client callback regression checks.
          --data-dir DIRECTORY
              Use an absolute settings directory instead of ProgramData\BijouShare\Client.
          --mount N:\
              Save the drive letter to use on this device.
          --name "Laptop name"
              Save this device's display name (1-100 characters; defaults to the computer name).
              Names may contain spaces, but no surrounding whitespace or control characters.
              The chosen name updates on each server on the next authenticated connection,
              including pending requests. Device identity and group assignments are retained.
          --help
              Show this help without creating files or connecting to the server.

        Install Dokany 2.3.x before mounting. Approve pending devices and assign groups on the server.
        The first approved connection pins the server key; use a trusted LAN address for setup.
        Legacy --create-device/--out and --import-enrollment commands remain available for migration.
        """;
}
