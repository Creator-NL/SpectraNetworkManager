using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SpectraNetworkManager.Core.Devices;
using SpectraNetworkManager.Platform.Windows.Mobile;

namespace SpectraNetworkManager.Ui;

public partial class MobilePairingWindow : Window
{
    private readonly MobileCompanionServer _server;
    private readonly string _lanIp;
    private readonly DispatcherTimer _timer;
    private int _remainingSeconds = 60;
    private string _currentUrl = "";

    public MobilePairingWindow(MobileCompanionServer server, string lanIp)
    {
        InitializeComponent();
        _server = server;
        _lanIp = lanIp;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTimerTick;

        AllowRuleChangesCheck.IsChecked = _server.AllowMobileRuleChanges;

        GenerateNewPairing();
    }

    private void GenerateNewPairing()
    {
        string token = _server.GeneratePairingToken();
        _currentUrl = $"http://{_lanIp}:{_server.Port}/?token={token}";

        PairingCodeText.Text = token;
        DirectUrlBox.Text = _currentUrl;

        _remainingSeconds = 60;
        CountdownText.Text = $"Token expires in {_remainingSeconds}s";

        // Render QR Code bitmap
        RenderQrBitmap(_currentUrl);

        _timer.Stop();
        _timer.Start();
    }

    private void RenderQrBitmap(string text)
    {
        try
        {
            var (matrix, size, margin) = QrCodeSvgRenderer.GenerateMatrix(text);
            int total = size + (margin * 2);

            // Create 32-bit BGRA pixel array
            int[] pixels = new int[total * total];
            int fg = unchecked((int)0xFF00E5FF); // Cyan
            int bg = unchecked((int)0xFF0A0E17); // Dark background

            for (int y = 0; y < total; y++)
            {
                for (int x = 0; x < total; x++)
                {
                    int mx = x - margin;
                    int my = y - margin;

                    bool isDark = (mx >= 0 && mx < size && my >= 0 && my < size) && matrix[my, mx];
                    pixels[(y * total) + x] = isDark ? fg : bg;
                }
            }

            var bmp = BitmapSource.Create(
                total, total, 96, 96,
                PixelFormats.Bgr32, null,
                pixels, total * 4);

            QrImage.Source = bmp;
        }
        catch
        {
            // Fallback
        }
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        _remainingSeconds--;
        if (_remainingSeconds <= 0)
        {
            CountdownText.Text = "Token expired. Click Refresh to generate a new code.";
            _timer.Stop();
        }
        else
        {
            CountdownText.Text = $"Token expires in {_remainingSeconds}s";
        }
    }

    private void OnRefreshTokenClick(object sender, RoutedEventArgs e)
    {
        GenerateNewPairing();
    }

    private void OnCopyUrlClick(object sender, RoutedEventArgs e)
    {
        System.Windows.Clipboard.SetText(_currentUrl);
        MessageBox.Show(this, "Pairing URL copied to clipboard!", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnPermissionChanged(object sender, RoutedEventArgs e)
    {
        _server.AllowMobileRuleChanges = AllowRuleChangesCheck.IsChecked == true;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        _timer.Stop();
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }
}
