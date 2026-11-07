using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32.SafeHandles;
using UsbGuard.Protocol;
using Forms = System.Windows.Forms;

namespace UsbGuard.Tray;

public partial class MainWindow : Window
{
    private readonly Forms.NotifyIcon tray;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private bool busy;
    private bool exiting;
    private int lastPendingCount;
    private ControlReply? lastReply;

    public MainWindow()
    {
        InitializeComponent();

        Forms.ContextMenuStrip menu = new();
        menu.Items.Add("Open USB Guard", null, (_, _) => Dispatcher.Invoke(ShowWindow));
        menu.Items.Add("Exit", null, (_, _) => Dispatcher.Invoke(() =>
        {
            exiting = true;
            timer.Stop();
            tray!.Dispose();
            System.Windows.Application.Current.Shutdown();
        }));
        tray = new Forms.NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "USB Guard",
            ContextMenuStrip = menu,
            Visible = true
        };
        tray.DoubleClick += (_, _) => Dispatcher.Invoke(ShowWindow);
        tray.BalloonTipClicked += (_, _) => Dispatcher.Invoke(ShowWindow);

        timer.Tick += async (_, _) => await SendAsync(new(ControlAction.Status, Guid.Empty, Guid.Empty));
        Loaded += async (_, _) =>
        {
            timer.Start();
            await SendAsync(new(ControlAction.Status, Guid.Empty, Guid.Empty));
        };
    }

    private void ShowWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!exiting)
        {
            e.Cancel = true;
            Hide();
        }
    }

    private void OnVolumeSelected(object sender, SelectionChangedEventArgs e) => UpdateSelection();

    private void UpdateSelection()
    {
        DriveView? drive = Volumes.SelectedItem as DriveView;
        VolumeStatus.Text = drive?.Detail ?? "Connect a USB flash drive to begin.";
        Findings.ItemsSource = drive?.Findings;
        HoldButton.IsEnabled = !busy && drive?.Phase == DrivePhase.AwaitingApproval;
        QuarantineButton.IsEnabled = HoldButton.IsEnabled;
        RetryButton.IsEnabled = !busy && drive?.Phase is DrivePhase.Error or DrivePhase.Held;
    }

    private async void OnHold(object sender, RoutedEventArgs e) => await ActAsync(ControlAction.KeepBlocked);

    private async void OnRetry(object sender, RoutedEventArgs e) => await ActAsync(ControlAction.Retry);

    private async void OnQuarantine(object sender, RoutedEventArgs e)
    {
        if (Volumes.SelectedItem is not DriveView drive)
            return;

        timer.Stop();
        try
        {
            MessageBoxResult result = MessageBox.Show(this,
                $"Move {drive.Findings.Count} flagged file(s) off {drive.Volume} into protected quarantine? " +
                "The originals will be removed from the USB drive after each copy is verified.",
                "Approve quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (result == MessageBoxResult.Yes)
                await SendAsync(new(ControlAction.Quarantine, drive.SessionId, drive.ApprovalId));
        }
        finally
        {
            if (!exiting)
                timer.Start();
        }
    }

    private Task ActAsync(ControlAction action) => Volumes.SelectedItem is DriveView drive
        ? SendAsync(new(action, drive.SessionId, drive.ApprovalId))
        : Task.CompletedTask;

    private async Task SendAsync(ControlRequest request)
    {
        if (busy)
            return;

        busy = true;
        UpdateSelection();
        try
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
            using NamedPipeClientStream pipe = new(".", ControlProtocol.PipeName,
                PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification, HandleInheritability.None);
            await pipe.ConnectAsync(timeout.Token);

            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pid) ||
                pid != WindowsServiceProcess.RunningProcessId("UsbGuard"))
                throw new IOException("The control pipe does not belong to the USB Guard service.");

            await ControlProtocol.WriteAsync(pipe, request, timeout.Token);
            ControlReply reply = await ControlProtocol.ReadAsync<ControlReply>(pipe, timeout.Token);
            Guid? selected = (Volumes.SelectedItem as DriveView)?.SessionId;
            bool changed = lastReply is null || !lastReply.Drives.SequenceEqual(reply.Drives, DriveComparer.Instance);
            if (changed)
            {
                Volumes.ItemsSource = reply.Drives;
                Volumes.SelectedItem = reply.Drives.FirstOrDefault(item => item.SessionId == selected) ??
                    reply.Drives.FirstOrDefault(item => item.Phase == DrivePhase.AwaitingApproval) ??
                    reply.Drives.FirstOrDefault();
            }
            lastReply = reply;

            ServiceStatus.Text = reply.Error ?? reply.ServiceStatus;
            int pendingCount = reply.Drives.Count(item => item.Phase == DrivePhase.AwaitingApproval);
            if (pendingCount > lastPendingCount && !IsVisible)
                tray.ShowBalloonTip(5000, "USB Guard", "USB access is blocked. Open USB Guard to review detections.",
                    Forms.ToolTipIcon.Warning);
            lastPendingCount = pendingCount;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OperationCanceledException
                                   or InvalidDataException or JsonException or Win32Exception or TimeoutException)
        {
            ServiceStatus.Text = "Cannot reach the USB Guard service.";
            lastReply = null;
            Volumes.ItemsSource = null;
        }
        finally
        {
            busy = false;
            UpdateSelection();
        }
    }

    private sealed class DriveComparer : System.Collections.Generic.IEqualityComparer<DriveView>
    {
        public static DriveComparer Instance { get; } = new();

        public bool Equals(DriveView? x, DriveView? y) => x is not null && y is not null &&
            x.SessionId == y.SessionId && x.ApprovalId == y.ApprovalId && x.Phase == y.Phase &&
            x.Detail == y.Detail && x.Volume == y.Volume && x.Findings.SequenceEqual(y.Findings);

        public int GetHashCode(DriveView value) => value.SessionId.GetHashCode();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
