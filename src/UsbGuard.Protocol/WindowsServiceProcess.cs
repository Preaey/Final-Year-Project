using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace UsbGuard.Protocol;

public static class WindowsServiceProcess
{
    public static uint RunningProcessId(string name)
    {
        using ServiceHandle manager = OpenSCManager(null, null, 0x0001); // SC_MANAGER_CONNECT
        if (manager.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        using ServiceHandle service = OpenService(manager, name, 0x0004); // SERVICE_QUERY_STATUS
        if (service.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        if (!QueryServiceStatusEx(service, 0, out ServiceStatus status,
                (uint)Marshal.SizeOf<ServiceStatus>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (status.State != 4 || status.ProcessId == 0) // SERVICE_RUNNING
            throw new IOException($"Windows service '{name}' is unavailable.");

        return status.ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint Type, State, Accepted, ExitCode, ServiceExitCode, CheckPoint,
            WaitHint, ProcessId, Flags;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level,
        out ServiceStatus status, uint size, out uint required);

    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
