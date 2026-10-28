using System.IO;
using System.Windows;

namespace SpectraNetworkManager.Ui;

public sealed record CleanDataOptions(
    bool CleanDnsHistory,
    bool CleanNetworkHistory,
    bool CleanAiHistory,
    bool CleanLogs,
    bool CleanCustomRules,
    bool CleanQuarantine);

public partial class CleanDataWindow : Window
{
    private readonly string _dataDir;
    public CleanDataOptions? SelectedOptions { get; private set; }

    public CleanDataWindow(string dataDir)
    {
        InitializeComponent();
        _dataDir = dataDir;
        Loaded += (_, _) => MeasureSizes();
    }

    private void MeasureSizes()
    {
        long dnsSize = GetFileSize(Path.Combine(_dataDir, "dns-history.db"));
        long netSize = GetFileSize(Path.Combine(_dataDir, "network-history.db"));
        long aiSize = GetFileSize(Path.Combine(_dataDir, "ai-investigations.db"));

        long logSize = 0;
        try
        {
            if (Directory.Exists(_dataDir))
            {
                foreach (var f in Directory.GetFiles(_dataDir, "*.log", SearchOption.TopDirectoryOnly))
                {
                    logSize += new FileInfo(f).Length;
                }
            }
        }
        catch { }

        DnsHistorySizeText.Text = FormatSize(dnsSize);
        NetworkHistorySizeText.Text = FormatSize(netSize);
        AiHistorySizeText.Text = FormatSize(aiSize);
        LogFilesSizeText.Text = FormatSize(logSize);

        long total = dnsSize + netSize + aiSize + logSize;
        CleanStatusText.Text = $"Total reclaimable history data: {FormatSize(total)}";
    }

    private static long GetFileSize(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
        }
        catch { }
        return 0;
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024 * 1024):F1} GB",
        >= 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        >= 1024 => $"{bytes / 1024.0:F0} KB",
        _ => $"{bytes} B"
    };

    private void OnExecuteCleanClick(object sender, RoutedEventArgs e)
    {
        if (CleanCustomRulesCheck.IsChecked == true)
        {
            var res = MessageBox.Show(this,
                "You selected to erase Custom DNS Rules & Client Groups.\n\nAre you sure you want to delete your custom rules?",
                "Confirm Delete Custom Rules", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res != MessageBoxResult.Yes) return;
        }

        if (CleanQuarantineCheck.IsChecked == true)
        {
            var res = MessageBox.Show(this,
                "You selected to permanently erase Quarantine Vault contents.\n\nQuarantined files cannot be recovered once purged. Continue?",
                "Confirm Purge Quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res != MessageBoxResult.Yes) return;
        }

        SelectedOptions = new CleanDataOptions(
            CleanDnsHistoryCheck.IsChecked == true,
            CleanNetworkHistoryCheck.IsChecked == true,
            CleanAiHistoryCheck.IsChecked == true,
            CleanLogsCheck.IsChecked == true,
            CleanCustomRulesCheck.IsChecked == true,
            CleanQuarantineCheck.IsChecked == true);

        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
