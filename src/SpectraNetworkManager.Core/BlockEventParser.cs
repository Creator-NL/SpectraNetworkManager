using System.Globalization;
using System.Xml.Linq;

namespace SpectraNetworkManager.Core;

/// <summary>Parses Windows event XML (as produced by wevtutil) for Filtering Platform events 5157 / 5152.</summary>
public static class BlockEventParser
{
    public static IReadOnlyList<BlockEvent> Parse(string eventsXml, Func<string, string>? pathConverter = null)
    {
        var result = new List<BlockEvent>();
        if (string.IsNullOrWhiteSpace(eventsXml)) return result;

        // wevtutil prints <Event>..</Event> back to back with no root element.
        var doc = XDocument.Parse("<Events>" + eventsXml + "</Events>");
        foreach (var ev in doc.Root!.Elements().Where(e => e.Name.LocalName == "Event"))
        {
            var system = Child(ev, "System");
            var data = Child(ev, "EventData");
            if (system is null || data is null) continue;

            int eventId = ToInt(Child(system, "EventID")?.Value);
            if (eventId is not (5157 or 5152)) continue;

            var fields = data.Elements()
                .Where(d => d.Name.LocalName == "Data" && d.Attribute("Name") is not null)
                .GroupBy(d => d.Attribute("Name")!.Value)
                .ToDictionary(g => g.Key, g => g.First().Value);

            string Field(string name) => fields.TryGetValue(name, out var v) ? v : "";

            string app = Field("Application");
            if (pathConverter is not null && app.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
                app = pathConverter(app);

            long.TryParse(Child(system, "EventRecordID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long recordId);
            var timeText = Child(system, "TimeCreated")?.Attribute("SystemTime")?.Value;
            var time = DateTimeOffset.TryParse(timeText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
                ? t.ToLocalTime() : DateTimeOffset.Now;

            result.Add(new BlockEvent(
                RecordId: recordId,
                Time: time,
                ProcessId: ToInt(Field("ProcessID")),
                Application: app,
                Inbound: Field("Direction") == "%%14592",   // %%14592 = Inbound, %%14593 = Outbound
                SourceAddress: Field("SourceAddress"),
                SourcePort: ToInt(Field("SourcePort")),
                DestinationAddress: Field("DestAddress"),
                DestinationPort: ToInt(Field("DestPort")),
                ProtocolNumber: ToInt(Field("Protocol")),
                IsPacketDrop: eventId == 5152));
        }
        return result;
    }

    private static XElement? Child(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName);

    private static int ToInt(string? s) =>
        int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
}
