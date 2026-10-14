using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Tests;

public class ParserTests
{
    [Fact]
    public void BlockEventParser_ParsesEvent5157XmlCorrectly()
    {
        string xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>5157</EventID>
    <EventRecordID>123456</EventRecordID>
    <TimeCreated SystemTime='2026-10-13T10:15:30.0000000Z'/>
  </System>
  <EventData>
    <Data Name='ProcessID'>4568</Data>
    <Data Name='Application'>\device\harddiskvolume3\Program Files\BadApp\bad.exe</Data>
    <Data Name='Direction'>%%14593</Data>
    <Data Name='SourceAddress'>192.168.1.100</Data>
    <Data Name='SourcePort'>54321</Data>
    <Data Name='DestAddress'>198.51.100.2</Data>
    <Data Name='DestPort'>443</Data>
    <Data Name='Protocol'>6</Data>
  </EventData>
</Event>";

        var events = BlockEventParser.Parse(xml, devPath => devPath.Replace(@"\device\harddiskvolume3", "C:"));
        Assert.Single(events);

        var ev = events[0];
        Assert.Equal(123456, ev.RecordId);
        Assert.Equal(4568, ev.ProcessId);
        Assert.Equal(@"C:\Program Files\BadApp\bad.exe", ev.Application);
        Assert.False(ev.Inbound); // %%14593 = Outbound
        Assert.Equal("192.168.1.100", ev.SourceAddress);
        Assert.Equal(54321, ev.SourcePort);
        Assert.Equal("198.51.100.2", ev.DestinationAddress);
        Assert.Equal(443, ev.DestinationPort);
        Assert.Equal(6, ev.ProtocolNumber);
        Assert.False(ev.IsPacketDrop);
    }

    [Fact]
    public void BlockEventParser_ParsesEvent5152PacketDrop()
    {
        string xml = @"
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>5152</EventID>
    <EventRecordID>999</EventRecordID>
  </System>
  <EventData>
    <Data Name='ProcessID'>0</Data>
    <Data Name='Direction'>%%14592</Data>
    <Data Name='Protocol'>17</Data>
  </EventData>
</Event>";

        var events = BlockEventParser.Parse(xml);
        Assert.Single(events);
        Assert.True(events[0].IsPacketDrop);
        Assert.True(events[0].Inbound); // %%14592 = Inbound
    }

    [Fact]
    public void AuthenticodeParser_ParsesValidJson()
    {
        string json = @"[
  { ""I"": 0, ""Status"": ""Valid"", ""Subject"": ""CN=\""Google LLC\"", O=\""Google LLC\"", L=Mountain View, S=California, C=US"", ""IsOs"": false },
  { ""I"": 1, ""Status"": ""NotSigned"", ""Subject"": """", ""IsOs"": false },
  { ""I"": 2, ""Status"": ""Valid"", ""Subject"": ""CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"", ""IsOs"": true }
]";

        var paths = new[] { @"C:\chrome.exe", @"C:\unsigned.exe", @"C:\notepad.exe" };
        var results = AuthenticodeParser.Parse(json, paths);

        Assert.Equal(3, results.Count);

        var chrome = results[@"C:\chrome.exe"];
        Assert.Equal(SignatureStatus.Valid, chrome.Status);
        Assert.Equal("Google LLC", chrome.Publisher);
        Assert.False(chrome.IsOsBinary);

        var unsigned = results[@"C:\unsigned.exe"];
        Assert.Equal(SignatureStatus.NotSigned, unsigned.Status);

        var notepad = results[@"C:\notepad.exe"];
        Assert.Equal(SignatureStatus.Valid, notepad.Status);
        Assert.Equal("Microsoft Windows", notepad.Publisher);
        Assert.True(notepad.IsOsBinary);
    }

    [Theory]
    [InlineData("CN=Example Corp", "Example Corp")]
    [InlineData("CN=\"Example, Inc.\", O=Example", "Example, Inc.")]
    [InlineData("O=\"Org Only\", C=US", "Org Only")]
    public void AuthenticodeParser_CommonNameExtraction(string subject, string expected)
    {
        Assert.Equal(expected, AuthenticodeParser.CommonName(subject));
    }
}
