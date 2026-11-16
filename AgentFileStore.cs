
using System.Text;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Agents.AI;

public sealed class AzureBlobAgentFileStore : AgentFileStore
{
    private const string DirectoryMarker = ".workspace-directory";
    private const int MaxTextBytes = 2 * 1024 * 1024;

    private readonly BlobContainerClient _container;
    private readonly string _root;

    public AzureBlobAgentFileStore(BlobServiceClient service, string containerName, string tenantId, string workspaceId)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(workspaceId))
            throw new ArgumentException("Tenant and workspace IDs are required.");

        _container = service.GetBlobContainerClient(containerName);
        _root = $"tenants/{SafeId(tenantId)}/workspaces/{SafeId(workspaceId)}/";
    }

    private static string SafeId(string value)
    {
        if (value.Length > 128 || !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException("Invalid workspace identifier.");

        return value;
    }

    private static string Normalize(string path, bool allowRoot = false)
    {
        if (string.IsNullOrEmpty(path))
        {
            if (allowRoot) return "";
            throw new ArgumentException("A file path is required.");
        }

        if (path.StartsWith('/') || path.Contains('\\') || path.Any(char.IsControl))
            throw new ArgumentException("Invalid workspace path.");

        var parts = path.TrimEnd('/').Split('/');

        if (parts.Any(p => p is "" or "." or ".." or DirectoryMarker))
            throw new ArgumentException("Invalid workspace path.");

        return string.Join("/", parts);
    }

    private string Key(string path) => _root + Normalize(path);

    public override async Task WriteAsync(string path, string content, CancellationToken cancellationToken = default)
    {
        var bytes = Encoding.UTF8.GetBytes(content);

        if (bytes.Length > MaxTextBytes)
            throw new InvalidOperationException("Workspace text file exceeds size limit.");

        var blob = _container.GetBlobClient(Key(path));

        await blob.UploadAsync(BinaryData.FromBytes(bytes),
            overwrite: true, cancellationToken: cancellationToken);
    }

    public override async Task<string?> ReadAsync(string path, CancellationToken cancellationToken = default)
    {
        var blob = _container.GetBlobClient(Key(path));

        try
        {
            var properties = await blob.GetPropertiesAsync(cancellationToken: cancellationToken);

            if (properties.Value.ContentLength > MaxTextBytes)
                throw new InvalidOperationException("Workspace text file exceeds size limit.");

            var result = await blob.DownloadContentAsync(cancellationToken);
            return result.Value.Content.ToString();
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public override async Task<bool> DeleteAsync(string path, CancellationToken cancellationToken = default)
    {
        var result = await _container.GetBlobClient(Key(path))
            .DeleteIfExistsAsync(DeleteSnapshotsOption.IncludeSnapshots,
                cancellationToken: cancellationToken);

        return result.Value;
    }

    public override async Task<bool> FileExistsAsync(string path, CancellationToken cancellationToken = default)
    {
        return await _container.GetBlobClient(Key(path)).ExistsAsync(cancellationToken);
    }

    public override async Task CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        string directory = Normalize(path, allowRoot: true);
        if (directory.Length == 0) return;

        var marker = _container.GetBlobClient(_root + directory + "/" + DirectoryMarker);

        await marker.UploadAsync(BinaryData.FromString(""),
            overwrite: true, cancellationToken: cancellationToken);
    }

    public override async Task<IReadOnlyList<FileStoreEntry>> ListChildrenAsync(string directory, CancellationToken cancellationToken = default)
    {
        string normalized = Normalize(directory, allowRoot: true);
        string prefix = _root + (normalized.Length == 0 ? "" : normalized + "/");

        var directories = new Dictionary<string, FileStoreEntry>(StringComparer.Ordinal);
        var files = new Dictionary<string, FileStoreEntry>(StringComparer.Ordinal);

        await foreach (var item in _container.GetBlobsByHierarchyAsync(
            prefix: prefix, delimiter: "/", cancellationToken: cancellationToken))
        {
            if (item.IsPrefix)
            {
                string name = item.Prefix![prefix.Length..].TrimEnd('/');

                if (name.Length > 0)
                    directories[name] = new FileStoreEntry(name, FileStoreEntry.Directory);
            }
            else if (item.IsBlob)
            {
                string name = item.Blob.Name[prefix.Length..];

                if (name.Length > 0 && name != DirectoryMarker)
                    files[name] = new FileStoreEntry(name, FileStoreEntry.File);
            }
        }

        return directories.Values.OrderBy(x => x.Name)
            .Concat(files.Values.OrderBy(x => x.Name))
            .ToList();
    }
}
