using System.ComponentModel;

namespace NetSentinel.Ui;

public sealed class AdapterListItem : INotifyPropertyChanged
{
    private bool _isSelected;
    public event PropertyChangedEventHandler? PropertyChanged;

    public int InterfaceIndex { get; init; }
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string CurrentDns { get; init; } = "";
    public string DisplayText => $"{Name} ({Description}) — DNS: {CurrentDns}";

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
