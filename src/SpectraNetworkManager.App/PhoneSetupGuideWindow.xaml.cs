using System.Windows;

namespace SpectraNetworkManager.Ui;

public partial class PhoneSetupGuideWindow : Window
{
    private readonly string _pcIp;
    private readonly int _port;

    public PhoneSetupGuideWindow(string pcIp, int port = 8765)
    {
        _pcIp = string.IsNullOrWhiteSpace(pcIp) ? "192.168.1.X" : pcIp;
        _port = port;
        InitializeComponent();

        AndroidProxyHostText.Text = _pcIp;
        AndroidDns1Text.Text = _pcIp;
        IosDnsText.Text = _pcIp;
    }

    private void OnCopyPingUrlClick(object sender, RoutedEventArgs e)
    {
        string url = $"http://{_pcIp}:{_port}/api/ping";
        try
        {
            System.Windows.Clipboard.SetText(url);
            MessageBox.Show(this,
                $"Link copied to clipboard!\n\n{url}\n\nOpen this link in Chrome or Safari on your phone to test connection.",
                "Link Copied",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch { }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
