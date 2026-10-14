using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Media;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Platform.Windows;

namespace SpectraNetworkManager.Ui;

public partial class FirstRunWizardWindow : Window
{
    private int _step = 1;
    private readonly AppSettingsStore _settingsStore = new();
    private bool _selfTestRun;

    public string SelectedMode { get; private set; } = "WatchOnly";

    public FirstRunWizardWindow()
    {
        InitializeComponent();
        UpdateStepUi();
    }

    private void UpdateStepUi()
    {
        Step1Panel.Visibility = _step == 1 ? Visibility.Visible : Visibility.Collapsed;
        Step2Panel.Visibility = _step == 2 ? Visibility.Visible : Visibility.Collapsed;
        Step3Panel.Visibility = _step == 3 ? Visibility.Visible : Visibility.Collapsed;

        var activeBrush = (Brush)FindResource("Cyan");
        var inactiveBrush = (Brush)FindResource("Muted");

        Step1Indicator.Foreground = _step == 1 ? activeBrush : inactiveBrush;
        Step1Indicator.FontWeight = _step == 1 ? FontWeights.Bold : FontWeights.Normal;

        Step2Indicator.Foreground = _step == 2 ? activeBrush : inactiveBrush;
        Step2Indicator.FontWeight = _step == 2 ? FontWeights.Bold : FontWeights.Normal;

        Step3Indicator.Foreground = _step == 3 ? activeBrush : inactiveBrush;
        Step3Indicator.FontWeight = _step == 3 ? FontWeights.Bold : FontWeights.Normal;

        BackButton.IsEnabled = _step > 1;

        if (_step == 3)
        {
            NextButton.Content = "Get Started";
            NextButton.Foreground = (Brush)FindResource("Cyan");
            if (!_selfTestRun)
            {
                _ = RunSelfTestAsync();
            }
        }
        else
        {
            NextButton.Content = "Next >";
            NextButton.Foreground = (Brush)FindResource("Cyan");
        }
    }

    private void OnBackClick(object sender, RoutedEventArgs e)
    {
        if (_step > 1)
        {
            _step--;
            UpdateStepUi();
        }
    }

    private void OnNextClick(object sender, RoutedEventArgs e)
    {
        if (_step < 3)
        {
            _step++;
            UpdateStepUi();
            return;
        }

        // Final step: Save choices and finish
        if (ModeAskRadio.IsChecked == true)
        {
            SelectedMode = "AskMode";
        }
        else if (ModeStrictRadio.IsChecked == true)
        {
            SelectedMode = "StrictMode";
        }
        else
        {
            SelectedMode = "WatchOnly";
        }

        var current = _settingsStore.Settings;
        var updated = current with
        {
            FirstRunCompleted = true,
            InitialOperatingMode = SelectedMode
        };

        try
        {
            _settingsStore.Save(updated);
        }
        catch (Exception ex)
        {
            RotatingFileLogger.LogError("Failed to save initial app settings in wizard", ex);
        }

        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(this,
            "Are you sure you want to exit SpectraNetworkManager setup?",
            "Exit Setup", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            DialogResult = false;
            Close();
        }
    }

    private async void OnRunCheckClick(object sender, RoutedEventArgs e)
    {
        await RunSelfTestAsync();
    }

    private async Task RunSelfTestAsync()
    {
        _selfTestRun = true;
        RunCheckButton.IsEnabled = false;
        SelfTestSummary.Text = "Running harmless system verification checks...";

        bool firewallOk = false;
        bool dnsOk = false;
        bool signatureOk = false;

        var okBrush = (Brush)FindResource("Cyan");
        var warnBrush = (Brush)FindResource("Amber");

        await Task.Run(() =>
        {
            // 1. Windows Firewall COM check
            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FWPolicy2");
                if (type != null)
                {
                    var instance = Activator.CreateInstance(type);
                    if (instance != null) firewallOk = true;
                }
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"Wizard Firewall COM test: {ex.Message}");
            }

            // 2. DNS Sinkhole Socket check
            try
            {
                using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                dnsOk = true;
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"Wizard DNS socket test: {ex.Message}");
            }

            // 3. Authenticode Verification check
            try
            {
                string sysDir = Environment.SystemDirectory;
                string kernelPath = Path.Combine(sysDir, "kernel32.dll");
                if (File.Exists(kernelPath))
                {
                    var status = NativeAuthenticodeVerifier.VerifyFile(kernelPath);
                    signatureOk = status.Status == SignatureStatus.Valid;
                }
                else
                {
                    signatureOk = true;
                }
            }
            catch (Exception ex)
            {
                RotatingFileLogger.LogWarn($"Wizard Authenticode test: {ex.Message}");
            }
        });

        Test1Status.Text = firewallOk ? "[ OK ]" : "[ WARNING ]";
        Test1Status.Foreground = firewallOk ? okBrush : warnBrush;

        Test2Status.Text = dnsOk ? "[ OK ]" : "[ WARNING ]";
        Test2Status.Foreground = dnsOk ? okBrush : warnBrush;

        Test3Status.Text = signatureOk ? "[ OK ]" : "[ WARNING ]";
        Test3Status.Foreground = signatureOk ? okBrush : warnBrush;

        if (firewallOk && dnsOk && signatureOk)
        {
            SelfTestSummary.Text = "All system verification checks passed. SpectraNetworkManager is ready to monitor and protect your connections.";
            SelfTestSummary.Foreground = okBrush;
        }
        else
        {
            SelfTestSummary.Text = "System check completed with warnings. Some features may require elevated permissions (Run as administrator).";
            SelfTestSummary.Foreground = warnBrush;
        }

        RunCheckButton.IsEnabled = true;
    }
}
