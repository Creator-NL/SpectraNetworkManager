using System.ComponentModel;

namespace SpectraNetworkManager.Ui;

public sealed class AdapterListItem : INotifyPropertyChanged
{
    private bool _isSelected;
    public event PropertyChangedEventHandler? PropertyChanged;

    public int InterfaceIndex { get; init; }
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string CurrentDns { get; init; } = "";
    public bool IsWireless { get; init; }
    public bool IsVirtual { get; init; }
    public bool HasDefaultGateway { get; init; }
    public string AdapterKind { get; init; } = "Ethernet";

    public string Icon => IsWireless ? "📶" : (IsVirtual ? "🖧" : "🔌");
    public string GatewayBadge => HasDefaultGateway ? " [Internet Gateway]" : "";
    public string DisplayText => $"{Icon} {Name} ({Description}){GatewayBadge} — DNS: {CurrentDns}";

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
            }
        }
    }
}
