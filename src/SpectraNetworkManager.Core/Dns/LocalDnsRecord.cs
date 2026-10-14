namespace SpectraNetworkManager.Sinkhole;

/// <summary>
/// A custom local DNS record (A, AAAA, CNAME, PTR, TXT) served authoritatively by SpectraNetworkManager
/// without querying upstream resolvers.
/// </summary>
public sealed record LocalDnsRecord(
    string Domain,
    string RecordType,
    string Value,
    uint Ttl = 300,
    bool Enabled = true
);
