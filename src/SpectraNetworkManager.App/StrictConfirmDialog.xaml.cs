using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Ui;

/// <summary>
/// The "keep these display settings?" safety net for strict mode. The result is true only if the user presses Keep;
/// closing the window, pressing Enter or letting the countdown run out all mean "switch strict mode off".
/// </summary>
public partial class StrictConfirmDialog : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _secondsLeft;

    public StrictConfirmDialog(Window owner, int seconds)
    {
        InitializeComponent();
        Owner = owner;
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
            var result = await ConnectivityProbe.RunAsync();
            ProbeText.Text = result.Ok
                ? "Connection check: OK. " + result.Message
                : "Connection check FAILED: " + result.Message + " If other programs also lost their connection, press 'Turn off now'.";
            ProbeText.Foreground = (Brush)FindResource(result.Ok ? "Cyan" : "Magenta");
        };

        Closed += (_, _) => _timer.Stop();
    }

    private void ShowCountdown() => CountdownText.Text = $"Switching off in {_secondsLeft} s";

    private void OnKeep(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        DialogResult = true;
    }
}
