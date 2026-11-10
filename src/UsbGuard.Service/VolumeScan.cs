using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace UsbGuard.Service;

internal sealed record Finding(string RelativePath, string Signature, byte[] Sha256);

internal static class VolumeScan
{
    private const int MaxDepth = 64;
    private const int MaxEntries = 100_000;
    private const int MaxFindings = 50;
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ShareRead = 1;
    private const uint OpenExisting = 3;
    private const int FileDispositionInfo = 4;
    private static readonly EnumerationOptions Enumeration = new()
    {
        IgnoreInaccessible = false,
        AttributesToSkip = 0
    };

    public static async Task<List<Finding>> RunAsync(WindowsVolume volume, ClamClient scanner,
        Action checkMount, Action<int> progress, CancellationToken token)
    {
        checkMount();
        string fileSystem = volume.GetFileSystem();
        if (!fileSystem.Equals("FAT32", StringComparison.OrdinalIgnoreCase))
            throw new IOException($"This prototype supports FAT32. Windows reports {fileSystem}.");

        await scanner.CheckAsync(token);
        List<Finding> findings = [];
        int scanned = 0;
        int visited = 0;
        await WalkAsync(volume.Root, 0);
        checkMount();
        return findings;

        async Task WalkAsync(string directory, int depth)
        {
            if (depth > MaxDepth)
                throw new IOException("The volume exceeds the directory depth limit.");

            foreach (string path in Directory.EnumerateFileSystemEntries(directory, "*", Enumeration))
            {
                token.ThrowIfCancellationRequested();
                if (++visited > MaxEntries)
                    throw new IOException("The volume exceeds the 100,000-entry scan limit.");

                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("The volume contains a reparse point.");

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    await WalkAsync(path, depth + 1);
                    continue;
                }

                if (!path.StartsWith(volume.Root, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("A file path is outside the volume.");

                string relative = path[volume.Root.Length..];
                if (relative.Length > 1024)
                    throw new IOException("A file path exceeds the scan limit.");
                _ = PathUnderRoot(volume.Root, relative);

                await using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                FileVerdict verdict;
                try
                {
                    verdict = await scanner.ScanAsync(file, token);
                }
                catch (IOException ex)
                {
                    throw new IOException($"{relative}: {ex.Message}", ex);
                }

                if (++scanned == 1 || scanned % 25 == 0)
                    progress(scanned);
                if (verdict.Signature is not null)
                {
                    if (findings.Count == MaxFindings)
                        throw new IOException("More than 50 files were flagged. The volume is still blocked.");

                    findings.Add(new Finding(relative, verdict.Signature, verdict.Sha256));
                }
            }
        }
    }

    public static async Task QuarantineAsync(WindowsVolume volume, IReadOnlyList<Finding> findings,
        string directory, Action checkMount, CancellationToken token)
    {
        foreach (Finding finding in findings)
        {
            token.ThrowIfCancellationRequested();
            checkMount();
            string path = PathUnderRoot(volume.Root, finding.RelativePath);
            using SafeFileHandle handle = CreateFile(path, GenericRead | DeleteAccess, ShareRead,
                IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot quarantine {finding.RelativePath}.");

            using FileStream source = new(handle, FileAccess.Read);
            if (source.Length > ClamClient.MaxFileBytes)
                throw new IOException($"{finding.RelativePath} changed after scanning.");

            string entry = Path.Combine(directory, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(entry);
            string copy = Path.Combine(entry, "content.bin");
            bool saved = false;
            try
            {
                await using (FileStream output = new(copy, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    await source.CopyToAsync(output, token);
                    output.Flush(flushToDisk: true);
                }

                await using FileStream savedFile = File.OpenRead(copy);
                byte[] digest = await SHA256.HashDataAsync(savedFile, token);
                if (!CryptographicOperations.FixedTimeEquals(digest, finding.Sha256))
                    throw new IOException($"{finding.RelativePath} changed after scanning.");

                await using (FileStream metadata = new(Path.Combine(entry, "details.json"),
                                 FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    await JsonSerializer.SerializeAsync(metadata, new
                    {
                        Volume = volume.Name,
                        OriginalPath = finding.RelativePath,
                        finding.Signature,
                        Sha256 = Convert.ToHexString(digest),
                        QuarantinedUtc = DateTimeOffset.UtcNow
                    }, cancellationToken: token);
                    metadata.Flush(flushToDisk: true);
                }

                checkMount();
                token.ThrowIfCancellationRequested();
                // Mark the exact opened file for deletion. Its quarantine copy has been flushed.
                byte deleteFile = 1;
                if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref deleteFile, sizeof(byte)))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot remove {finding.RelativePath}.");

                saved = true;
            }
            finally
            {
                if (!saved)
                    Directory.Delete(entry, recursive: true);
            }
        }
    }

    private static string PathUnderRoot(string root, string relative)
    {
        if (Path.IsPathRooted(relative) || relative.Contains(':') || relative.Contains('/') ||
            relative.Split('\\').Any(part => part is "" or "." or ".."))
            throw new IOException("The volume contains an unsupported relative path.");

        return Path.Combine(root, relative);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass,
        ref byte info, uint size);
}
