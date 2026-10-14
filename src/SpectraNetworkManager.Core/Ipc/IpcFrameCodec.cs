using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace SpectraNetworkManager.Core.Ipc;

/// <summary>
/// Encodes and decodes length-prefixed frames for reliable IPC streaming.
/// Frame format: 4-byte little-endian length followed by UTF-8 JSON payload.
/// </summary>
public static class IpcFrameCodec
{
    public const int MaxFrameSize = 16 * 1024 * 1024; // 16 MB max frame size safety limit

    /// <summary>
    /// Writes an IpcMessage as a length-prefixed frame to the stream.
    /// </summary>
    public static async Task WriteMessageAsync(Stream stream, IpcMessage message, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);

        string json = JsonSerializer.Serialize(message);
        byte[] payloadBytes = Encoding.UTF8.GetBytes(json);

        if (payloadBytes.Length > MaxFrameSize)
            throw new InvalidOperationException($"IPC payload size {payloadBytes.Length} exceeds maximum allowed {MaxFrameSize} bytes.");

        byte[] lengthHeader = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lengthHeader, payloadBytes.Length);

        await stream.WriteAsync(lengthHeader, ct).ConfigureAwait(false);
        await stream.WriteAsync(payloadBytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the next IpcMessage frame from the stream. Returns null on clean stream closure.
    /// </summary>
    public static async Task<IpcMessage?> ReadMessageAsync(Stream stream, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        byte[] lengthHeader = new byte[4];
        int headerBytesRead = 0;
        while (headerBytesRead < 4)
        {
            int read = await stream.ReadAsync(lengthHeader.AsMemory(headerBytesRead, 4 - headerBytesRead), ct).ConfigureAwait(false);
            if (read == 0)
            {
                if (headerBytesRead == 0) return null; // Clean EOF
                throw new EndOfStreamException("Incomplete frame length header read from IPC stream.");
            }
            headerBytesRead += read;
        }

        int frameLength = BinaryPrimitives.ReadInt32LittleEndian(lengthHeader);
        if (frameLength < 0 || frameLength > MaxFrameSize)
            throw new InvalidOperationException($"Invalid IPC frame length received: {frameLength} bytes.");

        if (frameLength == 0)
            return new IpcMessage();

        byte[] payloadBytes = new byte[frameLength];
        int payloadBytesRead = 0;
        while (payloadBytesRead < frameLength)
        {
            int read = await stream.ReadAsync(payloadBytes.AsMemory(payloadBytesRead, frameLength - payloadBytesRead), ct).ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException($"Premature EOF while reading IPC payload: expected {frameLength} bytes, read {payloadBytesRead}.");
            payloadBytesRead += read;
        }

        string json = Encoding.UTF8.GetString(payloadBytes);
        return JsonSerializer.Deserialize<IpcMessage>(json);
    }
}
