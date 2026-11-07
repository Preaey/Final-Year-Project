using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using UsbGuard.Protocol;

namespace UsbGuard.Service;

internal sealed class ControlServer(GuardWorker worker, ILogger<ControlServer> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        PipeSecurity security = new();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));

        using NamedPipeServerStream pipe = NamedPipeServerStreamAcl.Create(ControlProtocol.PipeName,
            PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            0, 0, security);

        while (!stoppingToken.IsCancellationRequested)
        {
            await pipe.WaitForConnectionAsync(stoppingToken);
            try
            {
                using CancellationTokenSource requestTime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                requestTime.CancelAfter(TimeSpan.FromSeconds(3));
                ControlRequest request = await ControlProtocol.ReadAsync<ControlRequest>(pipe, requestTime.Token);
                await ControlProtocol.WriteAsync(pipe, worker.Handle(request), requestTime.Token);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or OperationCanceledException)
            {
                logger.LogDebug("Control request ended. {Error}", ex.Message);
            }
            finally
            {
                pipe.Disconnect();
            }
        }
    }
}
