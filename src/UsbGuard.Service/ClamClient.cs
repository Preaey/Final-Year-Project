using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using UsbGuard.Protocol;

namespace UsbGuard.Service;

internal sealed record FileVerdict(string? Signature, byte[] Sha256);

internal sealed class ClamClient
{
    private const int Port = 3310;
    public const long MaxFileBytes = 64 * 1024 * 1024;

    public async Task CheckAsync(CancellationToken token)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using TcpClient client = await ConnectAsync(timeout.Token);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync("zPING\0"u8.ToArray(), timeout.Token);
        if (await ReadReplyAsync(stream, timeout.Token) != "PONG")
            throw new IOException("ClamAV did not acknowledge the scan request.");
    }

    public async Task<FileVerdict> ScanAsync(FileStream file, CancellationToken token)
    {
        if (file.Length > MaxFileBytes)
            throw new IOException("File exceeds the 64 MiB scan limit.");

        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromMinutes(2));
        using TcpClient client = await ConnectAsync(timeout.Token);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync("zINSTREAM\0"u8.ToArray(), timeout.Token);

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] chunk = new byte[4 + 64 * 1024];
        long total = 0;
        int count;
        while ((count = await file.ReadAsync(chunk.AsMemory(4), timeout.Token)) != 0)
        {
            total += count;
            if (total > MaxFileBytes)
                throw new IOException("File exceeds the 64 MiB scan limit.");

            hash.AppendData(chunk, 4, count);
            BinaryPrimitives.WriteInt32BigEndian(chunk, count);
            await stream.WriteAsync(chunk.AsMemory(0, 4 + count), timeout.Token);
        }

        if (total != file.Length)
            throw new IOException("File length changed during scanning.");

        await stream.WriteAsync(new byte[4], timeout.Token);
        string reply = await ReadReplyAsync(stream, timeout.Token);
        string? signature = reply switch
        {
            "stream: OK" => null,
            _ when reply.StartsWith("stream: ", StringComparison.Ordinal) &&
                   reply.EndsWith(" FOUND", StringComparison.Ordinal) && reply.Length > 14
                => reply[8..^6],
            _ => throw new IOException($"ClamAV could not scan the file. {reply}")
        };

        return new FileVerdict(signature, hash.GetHashAndReset());
    }

    private static async Task<TcpClient> ConnectAsync(CancellationToken token)
    {
        TcpClient client = new(AddressFamily.InterNetwork) { NoDelay = true };
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, Port, token);
            uint expectedPid = WindowsServiceProcess.RunningProcessId("clamd");
            int clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;
            if (!IsClamServiceConnection(clientPort, expectedPid))
                throw new IOException("The ClamAV connection does not belong to the clamd service.");
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadReplyAsync(Stream stream, CancellationToken token)
    {
        byte[] buffer = new byte[4096];
        int length = 0;
        while (length < buffer.Length)
        {
            int bytes = await stream.ReadAsync(buffer.AsMemory(length), token);
            if (bytes == 0)
                break;

            int end = Array.IndexOf(buffer, (byte)0, length, bytes);
            if (end >= 0)
                return Encoding.UTF8.GetString(buffer, 0, end);

            length += bytes;
        }

        throw new IOException("ClamAV returned an incomplete or oversized response.");
    }

    private static bool IsClamServiceConnection(int clientPort, uint expectedPid)
    {
        const uint IpV4 = 2;
        const int OwnerPidConnections = 4;
        const int RowBytes = 24;
        const int InsufficientBuffer = 122;

        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, IpV4, OwnerPidConnections, 0);
        for (int attempt = 0; attempt < 3 && size is >= 4 and <= 16 * 1024 * 1024; attempt++)
        {
            int allocated = size;
            IntPtr table = Marshal.AllocHGlobal(allocated);
            try
            {
                uint result = GetExtendedTcpTable(table, ref size, false, IpV4, OwnerPidConnections, 0);
                if (result == InsufficientBuffer)
                    continue;
                if (result != 0)
                    throw new Win32Exception((int)result);

                int count = Marshal.ReadInt32(table);
                if (count < 0 || count > (allocated - 4) / RowBytes)
                    throw new IOException("Windows returned an invalid TCP owner table.");

                for (int row = 0; row < count; row++)
                {
                    IntPtr entry = table + 4 + row * RowBytes;
                    const int loopback = 0x0100007F;
                    if (Marshal.ReadInt32(entry) == 5 && // MIB_TCP_STATE_ESTAB
                        Marshal.ReadInt32(entry, 4) == loopback &&
                        Marshal.ReadInt32(entry, 12) == loopback &&
                        PortAt(entry, 8) == Port && PortAt(entry, 16) == clientPort &&
                        unchecked((uint)Marshal.ReadInt32(entry, 20)) == expectedPid)
                        return true;
                }

                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(table);
            }
        }

        return false;
    }

    private static int PortAt(IntPtr row, int offset) =>
        (Marshal.ReadByte(row, offset) << 8) | Marshal.ReadByte(row, offset + 1);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort,
        uint addressFamily, int tableClass, uint reserved);
}
