namespace BijouShare.Shared;

/// <summary>Prevents independent service/setup processes from overwriting the same private state.</summary>
public sealed class StorageLease : IDisposable
{
    private readonly FileStream stream;

    private StorageLease(FileStream stream) => this.stream = stream;

    public static StorageLease Acquire(string directory, bool includeLocalService = false)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
            throw new ArgumentException("The private data directory must be an absolute path.", nameof(directory));
        PrivateStorage.SecureDirectory(directory, includeLocalService);
        var path = Path.Combine(directory, ".instance.lock");
        try
        {
            if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new UnauthorizedAccessException("The instance lock must be an ordinary file inside the private data directory.");
        }
        catch (FileNotFoundException) { }
        FileStream stream;
        try
        {
            stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33)
        {
            throw new IOException("Another BijouShare process is using this data directory. Stop that service or console instance before running setup or starting another instance.", ex);
        }

        // The lease is the open handle itself. Never truncate an existing lock file or follow its content.
        return new StorageLease(stream);
    }

    public void Dispose() => stream.Dispose();
}
