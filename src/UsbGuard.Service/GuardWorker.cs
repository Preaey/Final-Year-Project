using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using UsbGuard.Protocol;

namespace UsbGuard.Service;

internal sealed class GuardWorker(ClamClient scanner, ILogger<GuardWorker> logger) : BackgroundService
{
    private readonly object gate = new();
    private readonly Dictionary<ulong, Session> sessions = [];
    private string serviceStatus = "Connecting to the USB Guard driver.";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using FilterPort port = FilterPort.Open();
                await MonitorAsync(port, stoppingToken);
            }
            catch (Exception ex) when (ex is IOException or Win32Exception)
            {
                lock (gate)
                    serviceStatus = "Driver unavailable. " + ex.Message;
                logger.LogWarning("{Error}", ex.Message);
            }

            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        }
    }

    private async Task MonitorAsync(FilterPort port, CancellationToken stoppingToken)
    {
        using CancellationTokenSource connection = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        Task activeJob = Task.CompletedTask;
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromSeconds(1));
            do
            {
                port.Ping();
                UpdateSessions(port);
                if (activeJob.IsCompleted)
                {
                    await activeJob;
                    activeJob = StartNextJob(port, connection.Token);
                }
            }
            while (await timer.WaitForNextTickAsync(connection.Token));
        }
        finally
        {
            await connection.CancelAsync();
            try
            {
                await activeJob;
            }
            finally
            {
                lock (gate)
                    sessions.Clear();
            }
        }
    }

    private void UpdateSessions(FilterPort port)
    {
        Dictionary<ulong, (WindowsVolume Volume, bool Released)> mounted = [];
        bool uncertain = false;
        foreach (WindowsVolume volume in WindowsVolume.Enumerate())
        {
            try
            {
                FilterState state = port.Query(volume.Device);
                if (state.Id != 0)
                    mounted.TryAdd(state.Id, (volume, state.Released));
            }
            catch (IOException)
            {
                // A volume can disappear while Windows is enumerating it.
                uncertain = true;
            }
        }

        lock (gate)
        {
            serviceStatus = uncertain ? "Guard active. Some volumes could not be inspected." :
                "Guard active. USB storage is scanned on insertion.";
            foreach (ulong id in sessions.Keys.Where(id => !mounted.ContainsKey(id)).ToArray())
                sessions.Remove(id);
            foreach (var (id, item) in mounted)
                sessions.TryAdd(id, new Session(id, item.Volume, item.Released));
        }
    }

    private Task StartNextJob(FilterPort port, CancellationToken token)
    {
        lock (gate)
        {
            Session? session = sessions.Values.FirstOrDefault(session =>
                session.Phase is DrivePhase.QuarantineQueued or DrivePhase.Queued);
            if (session is null)
                return Task.CompletedTask;

            bool quarantine = session.Phase == DrivePhase.QuarantineQueued;
            session.Phase = quarantine ? DrivePhase.Quarantining : DrivePhase.Scanning;
            session.Detail = quarantine ? "Quarantining approved files." : "Checking the volume.";
            return Task.Run(() => ProcessAsync(port, session, quarantine, token), token);
        }
    }

    private async Task ProcessAsync(FilterPort port, Session session, bool quarantine, CancellationToken token)
    {
        FilterState CheckState()
        {
            token.ThrowIfCancellationRequested();
            FilterState state = port.Query(session.Volume.Device);
            if (state.Id != session.DriverId)
                throw new IOException("The original volume is no longer connected.");
            return state;
        }

        void CheckMount()
        {
            if (CheckState().Released)
                throw new IOException("This volume was already released.");
        }

        void Progress(int count)
        {
            lock (gate)
                session.Detail = $"Scanned {count:N0} files. Access is blocked.";
        }

        try
        {
            if (CheckState().Released)
            {
                lock (gate)
                {
                    session.Phase = DrivePhase.Released;
                    session.Detail = "Already released for this connection.";
                    session.Findings = [];
                }
                return;
            }

            if (quarantine)
            {
                await VolumeScan.QuarantineAsync(session.Volume, session.Findings, OpenQuarantine(),
                    CheckMount, token);
                lock (gate)
                {
                    session.Phase = DrivePhase.Scanning;
                    session.Detail = "Verifying the volume after quarantine.";
                    session.Findings = [];
                }
            }

            List<Finding> findings = await VolumeScan.RunAsync(session.Volume, scanner, CheckMount, Progress, token);
            if (findings.Count == 0)
            {
                CheckMount();
                port.Release(session.Volume.Device, session.DriverId);
                lock (gate)
                {
                    session.Phase = DrivePhase.Released;
                    session.Detail = "Scan completed with no detections. Access is allowed.";
                }
                logger.LogInformation("Released volume {Volume}.", session.Volume.Name);
            }
            else
            {
                lock (gate)
                {
                    session.Findings = findings;
                    session.ApprovalId = Guid.NewGuid();
                    session.Phase = DrivePhase.AwaitingApproval;
                    session.Detail = $"{findings.Count} flagged files. Access is blocked.";
                }
                logger.LogWarning("Volume {Volume} held with {Count} findings.", session.Volume.Name, findings.Count);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // A disconnected service session cannot issue further release decisions.
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   Win32Exception or System.Net.Sockets.SocketException or
                                   OperationCanceledException or ArgumentException)
        {
            lock (gate)
            {
                session.Phase = DrivePhase.Error;
                session.Detail = ex is OperationCanceledException
                    ? "The scanner timed out. Access is blocked."
                    : ex.Message;
                session.Findings = [];
            }
            logger.LogWarning("Volume {Volume} remains blocked. {Error}", session.Volume.Name, ex.Message);
        }
    }

    public ControlReply Handle(ControlRequest request)
    {
        lock (gate)
        {
            string? error = null;
            if (request.Action != ControlAction.Status)
            {
                Session? session = sessions.Values.FirstOrDefault(item => item.Id == request.SessionId);
                error = session is null ? "That volume session has ended." : Apply(session, request);
            }

            DriveView[] drives = sessions.Values.Select(session => new DriveView(session.Id, session.ApprovalId,
                session.Volume.Name, session.Phase, session.Detail,
                session.Findings.Select(finding => new FindingView(finding.RelativePath, finding.Signature)).ToArray()))
                .ToArray();
            return new ControlReply(serviceStatus, drives, error);
        }
    }

    private static string? Apply(Session session, ControlRequest request)
    {
        if (request.Action == ControlAction.Retry && session.Phase is DrivePhase.Held or DrivePhase.Error)
        {
            session.Phase = DrivePhase.Queued;
            session.Findings = [];
            session.Detail = "Waiting to scan again.";
            return null;
        }

        if (session.Phase != DrivePhase.AwaitingApproval || request.ApprovalId != session.ApprovalId ||
            request.Action is not (ControlAction.KeepBlocked or ControlAction.Quarantine))
            return "The volume has changed state. Refresh its status and try again.";

        session.ApprovalId = Guid.Empty;
        if (request.Action == ControlAction.Quarantine)
        {
            session.Phase = DrivePhase.QuarantineQueued;
            session.Detail = "Quarantine approved. Waiting for the service.";
        }
        else
        {
            session.Phase = DrivePhase.Held;
            session.Detail = "User chose to keep access blocked.";
        }
        return null;
    }

    private static string OpenQuarantine()
    {
        DirectoryInfo directory = new(Path.Combine(AppContext.BaseDirectory, "Quarantine"));
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(true, false);
        foreach (WellKnownSidType sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }

        if (!directory.Exists)
            directory.Create(security);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("The quarantine directory is a reparse point.");
        directory.SetAccessControl(security);
        return directory.FullName;
    }

    private sealed class Session(ulong driverId, WindowsVolume volume, bool released)
    {
        public ulong DriverId { get; } = driverId;
        public Guid Id { get; } = Guid.NewGuid();
        public WindowsVolume Volume { get; } = volume;
        public Guid ApprovalId { get; set; }
        public DrivePhase Phase { get; set; } = released ? DrivePhase.Released : DrivePhase.Queued;
        public string Detail { get; set; } = released ? "Already released for this connection." : "Waiting to scan.";
        public IReadOnlyList<Finding> Findings { get; set; } = [];
    }
}
