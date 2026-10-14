using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using SpectraNetworkManager.Platform.Windows;

namespace SpectraNetworkManager.Ui;

/// <summary>
/// Safety confirmation dialog for pointing system network adapters at SpectraNetworkManager's DNS server.
/// If the user loses internet or does not explicitly click "Keep", DNS settings are automatically reverted.
/// </summary>
public partial class SystemDnsConfirmDialog : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly SystemDnsSwitchManager _manager;
    private int _secondsLeft;

    public SystemDnsConfirmDialog(Window owner, SystemDnsSwitchManager manager, int seconds = 60)
    {
        InitializeComponent();
        Owner = owner;
        _manager = manager;
        _secondsLeft = seconds;
        ShowCountdown();

        _timer.Tick += (_, _) =>
        {
            _secondsLeft--;
            ShowCountdown();
            if (_secondsLeft <= 0)
            {
                _timer.Stop();
                DialogResult = false;
            }
        };

        Loaded += async (_, _) =>
        {
            _timer.Start();
            var result = await _manager.ProbeResolutionAsync();
            if (result.LocalOk && result.SystemOk)
            {
                ProbeText.Text = "Connection check: OK. " + result.Details;
                ProbeText.Foreground = (Brush)FindResource("Cyan");
            }
            else
            {
                ProbeText.Text = "Connection check WARNING: " + result.Details + " If web browsing fails, click 'Restore original DNS now'.";
                ProbeText.Foreground = (Brush)FindResource("Magenta");
            }
        };

        Closed += (_, _) => _timer.Stop();
    }

    private void ShowCountdown() => CountdownText.Text = $"Restoring original DNS in {_secondsLeft} s";

    private void OnKeep(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        DialogResult = true;
    }
}
