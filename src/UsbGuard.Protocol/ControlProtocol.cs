using System.Buffers.Binary;
using System.Text.Json;

namespace UsbGuard.Protocol;

public enum DrivePhase
{
    Queued, Scanning, AwaitingApproval, Held, QuarantineQueued, Quarantining, Released, Error
}

public enum ControlAction { Status, Quarantine, KeepBlocked, Retry }

public sealed record ControlRequest(ControlAction Action, Guid SessionId, Guid ApprovalId);
public sealed record FindingView(string Path, string Signature);
public sealed record DriveView(Guid SessionId, Guid ApprovalId, string Volume,
    DrivePhase Phase, string Detail, IReadOnlyList<FindingView> Findings);
public sealed record ControlReply(string ServiceStatus, IReadOnlyList<DriveView> Drives, string? Error);

public static class ControlProtocol
{
    public const string PipeName = "UsbGuard.Control.v1";
    private const int MaxFrame = 1024 * 1024;

    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken token)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(message);
        if (body.Length > MaxFrame)
            throw new InvalidDataException("Control message is too large.");

        byte[] length = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, body.Length);
        await stream.WriteAsync(length, token);
        await stream.WriteAsync(body, token);
        await stream.FlushAsync(token);
    }

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken token)
    {
        byte[] length = new byte[4];
        await stream.ReadExactlyAsync(length, token);
        int size = BinaryPrimitives.ReadInt32LittleEndian(length);
        if (size <= 0 || size > MaxFrame)
            throw new InvalidDataException("Invalid control message length.");

        byte[] body = new byte[size];
        await stream.ReadExactlyAsync(body, token);
        return JsonSerializer.Deserialize<T>(body) ??
            throw new InvalidDataException("Empty control message.");
    }
}
