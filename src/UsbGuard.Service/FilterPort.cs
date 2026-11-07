using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace UsbGuard.Service;

internal readonly record struct FilterState(ulong Id, bool Released);

internal sealed class FilterPort(SafeFileHandle handle) : IDisposable
{
    public static FilterPort Open()
    {
        int result = FilterConnectCommunicationPort(@"\UsbGuardPort", 0, IntPtr.Zero, 0, IntPtr.Zero,
            out SafeFileHandle port);
        if (result < 0)
        {
            port?.Dispose();
            throw Error("Connect to the minifilter", result);
        }
        return new FilterPort(port);
    }

    public FilterState Query(string device) => Send(1, device, 0);

    public void Ping() => Send(3, "", 0);

    public void Release(string device, ulong expectedId)
    {
        FilterState state = Send(2, device, expectedId);
        if (state.Id != expectedId || !state.Released)
            throw new IOException("The driver did not release the scanned volume.");
    }

    private FilterState Send(uint operation, string device, ulong expectedId)
    {
        const int nameCapacity = 128;
        if (device.Length >= nameCapacity)
            throw new IOException("The Windows volume name is too long.");

        byte[] request = new byte[16 + nameCapacity * 2];
        BinaryPrimitives.WriteUInt32LittleEndian(request, operation);
        BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(8), expectedId);
        Encoding.Unicode.GetBytes(device, request.AsSpan(16));

        byte[] reply = new byte[16];
        int result = FilterSendMessage(handle, request, (uint)request.Length, reply,
            (uint)reply.Length, out uint bytes);
        if (result < 0)
            throw Error("Read minifilter state", result);
        if (bytes != reply.Length)
            throw new IOException("Unexpected minifilter response size.");

        return new FilterState(BinaryPrimitives.ReadUInt64LittleEndian(reply),
            BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(8)) != 0);
    }

    private static IOException Error(string action, int hresult)
    {
        string detail = Marshal.GetExceptionForHR(hresult)?.Message ??
            new Win32Exception(hresult & 0xffff).Message;
        return new IOException($"{action} failed (0x{hresult:X8}). {detail}");
    }

    public void Dispose() => handle.Dispose();

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int FilterConnectCommunicationPort(string portName, uint options,
        IntPtr context, ushort contextSize, IntPtr securityAttributes, out SafeFileHandle port);

    [DllImport("fltlib.dll", ExactSpelling = true)]
    private static extern int FilterSendMessage(SafeFileHandle port, byte[] inBuffer, uint inSize,
        [Out] byte[] outBuffer, uint outSize, out uint bytesReturned);
}
