using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace UsbGuard.Service;

internal sealed record WindowsVolume(string Device, string Root, string GuidRoot, string Name)
{
    public string GetFileSystem()
    {
        StringBuilder fileSystem = new(64);
        if (!GetVolumeInformation(GuidRoot, null, 0, out _, out _, out _, fileSystem,
                (uint)fileSystem.Capacity))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return fileSystem.ToString();
    }

    public static IEnumerable<WindowsVolume> Enumerate()
    {
        StringBuilder guid = new(128);
        using VolumeFindHandle find = FindFirstVolume(guid, (uint)guid.Capacity);
        if (find.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        do
        {
            string volumeGuid = guid.ToString();
            StringBuilder deviceName = new(1024);
            if (volumeGuid.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase) &&
                QueryDosDevice(volumeGuid[4..^1], deviceName, (uint)deviceName.Capacity) != 0)
            {
                string device = deviceName.ToString().Split('\0')[0];
                if (device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                    yield return new WindowsVolume(device, @"\\?\GLOBALROOT" + device + "\\",
                        volumeGuid, DisplayName(volumeGuid));
            }
        }
        while (FindNextVolume(find, guid, (uint)guid.Capacity));

        int error = Marshal.GetLastWin32Error();
        if (error != 18) // ERROR_NO_MORE_FILES
            throw new Win32Exception(error);
    }

    private static string DisplayName(string volumeGuid)
    {
        char[] paths = new char[1024];
        if (GetVolumePathNamesForVolumeName(volumeGuid, paths, (uint)paths.Length, out _))
        {
            int firstEnd = Array.IndexOf(paths, '\0');
            if (firstEnd > 0)
                return new string(paths, 0, firstEnd) + "  (" + volumeGuid[4..^1] + ")";
        }

        return volumeGuid[4..^1];
    }

    private sealed class VolumeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public VolumeFindHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindVolumeClose(handle);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern VolumeFindHandle FindFirstVolume(StringBuilder volume, uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextVolume(VolumeFindHandle find, StringBuilder volume, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindVolumeClose(IntPtr find);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string name, StringBuilder target, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumePathNamesForVolumeName(string volume, [Out] char[] paths,
        uint length, out uint required);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetVolumeInformation(string root, StringBuilder? label, uint labelSize,
        out uint serial, out uint componentLength, out uint flags, StringBuilder fileSystem, uint size);
}
