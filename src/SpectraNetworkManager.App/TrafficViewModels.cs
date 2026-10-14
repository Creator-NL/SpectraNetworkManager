using System.IO;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Ui;

public sealed class TopTalkerViewModel
{
    public string Program { get; }
    public string ProgramName { get; }
    public long BytesIn { get; }
    public long BytesOut { get; }
    public long TotalBytes { get; }
    public DateTimeOffset LastActive { get; }

    public string DownloadFormatted => Display.Bytes(BytesIn);
    public string UploadFormatted => Display.Bytes(BytesOut);
    public string TotalFormatted => Display.Bytes(TotalBytes);
    public string LastActiveFormatted => LastActive.ToLocalTime().ToString("HH:mm:ss");

    public TopTalkerViewModel(string program, long bytesIn, long bytesOut, DateTimeOffset lastActive)
    {
        Program = program;
        ProgramName = Path.GetFileName(program);
        if (string.IsNullOrEmpty(ProgramName)) ProgramName = program;
        BytesIn = bytesIn;
        BytesOut = bytesOut;
        TotalBytes = bytesIn + bytesOut;
        LastActive = lastActive;
    }
}

public sealed class ConnectionHistoryViewModel
{
    public string Program { get; }
    public string ProgramName { get; }
    public string Remote { get; }
    public int Port { get; }
    public string Proto { get; }
    public DateTimeOffset FirstSeen { get; }
    public DateTimeOffset LastSeen { get; }

    public string FirstSeenFormatted => FirstSeen.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string LastSeenFormatted => LastSeen.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public ConnectionHistoryViewModel(string program, string remote, int port, string proto, DateTimeOffset firstSeen, DateTimeOffset lastSeen)
    {
        Program = program;
        ProgramName = Path.GetFileName(program);
        if (string.IsNullOrEmpty(ProgramName)) ProgramName = program;
        Remote = remote;
        Port = port;
        Proto = proto;
        FirstSeen = firstSeen;
        LastSeen = lastSeen;
    }
}
