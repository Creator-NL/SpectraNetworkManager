using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using SpectraNetworkManager.Core;
using SpectraNetworkManager.Sinkhole;
using Button = System.Windows.Controls.Button;
using KeyEventArgs = System.Windows.Input.KeyEventArgs;

namespace SpectraNetworkManager.Ui;

public sealed record CustomRuleRow(string Domain);

public sealed record SubscriptionRow(string Name, string Url, string Status, string FileSize, string LastModified, bool Exists);

public partial class DnsCustomRulesWindow : Window
{
    private readonly DnsService _sink;
    private readonly Action _onChanged;

    private readonly ObservableCollection<CustomRuleRow> _blocked = new();
    private readonly ObservableCollection<CustomRuleRow> _allowed = new();
    private readonly ObservableCollection<SubscriptionRow> _subscriptions = new();

    private ICollectionView _blockedView;
    private ICollectionView _allowedView;

    public DnsCustomRulesWindow(DnsService sink, Action onChanged)
    {
        InitializeComponent();
        _sink = sink;
        _onChanged = onChanged;

        _blockedView = CollectionViewSource.GetDefaultView(_blocked);
        _blockedView.Filter = FilterBlocked;
        BlockedGrid.ItemsSource = _blockedView;

        _allowedView = CollectionViewSource.GetDefaultView(_allowed);
        _allowedView.Filter = FilterAllowed;
        AllowedGrid.ItemsSource = _allowedView;

        SubscriptionsGrid.ItemsSource = _subscriptions;

        StoragePathText.Text = EngineStoragePaths.BlocklistsDirectory;

        LoadData();
    }

    private void LoadData()
    {
        _blocked.Clear();
        foreach (var rule in _sink.Settings.CustomBlock)
        {
            _blocked.Add(new CustomRuleRow(rule));
        }

        _allowed.Clear();
        foreach (var rule in _sink.Settings.CustomAllow)
        {
            _allowed.Add(new CustomRuleRow(rule));
        }

        TabBlocked.Content = $"🚫 Custom Blocked ({_blocked.Count})";
        TabAllowed.Content = $"🛡️ Custom Whitelist ({_allowed.Count})";

        LoadSubscriptions();
    }

    private void LoadSubscriptions()
    {
        _subscriptions.Clear();
        string folder = EngineStoragePaths.BlocklistsDirectory;

        foreach (var list in _sink.Settings.Lists)
        {
            string file = GetListFilePath(folder, list);
            bool exists = File.Exists(file);
            string status = exists ? "Downloaded & Active" : "Not downloaded yet";
            string size = "-";
            string lastMod = "-";

            if (exists)
            {
                try
                {
                    var fi = new FileInfo(file);
                    size = FormatBytes(fi.Length);
                    lastMod = fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm");
                }
                catch { }
            }

            _subscriptions.Add(new SubscriptionRow(list.Name, list.Url, status, size, lastMod, exists));
        }

        TabSubscriptions.Content = $"📁 Subscription Lists ({_subscriptions.Count})";
        SubscriptionTotalText.Text = $"Total Active Domains on Blocklists: {_sink.BlockedDomainCount:N0}";
    }

    private static string GetListFilePath(string folder, BlocklistSource list)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(list.Url.ToLowerInvariant()));
        string safe = new string(list.Name.Where(char.IsLetterOrDigit).ToArray());
        if (safe.Length > 24) safe = safe[..24];
        return Path.Combine(folder, $"{safe}-{Convert.ToHexString(hash, 0, 4).ToLowerInvariant()}.txt");
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024):F1} MB";
    }

    private bool FilterBlocked(object item)
    {
        if (item is not CustomRuleRow row) return false;
        string q = SearchBlockedBox.Text.Trim();
        return q.Length == 0 || row.Domain.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private bool FilterAllowed(object item)
    {
        if (item is not CustomRuleRow row) return false;
        string q = SearchAllowedBox.Text.Trim();
        return q.Length == 0 || row.Domain.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void OnSearchBlockedChanged(object sender, TextChangedEventArgs e) => _blockedView.Refresh();
    private void OnSearchAllowedChanged(object sender, TextChangedEventArgs e) => _allowedView.Refresh();

    private void OnTabChanged(object sender, RoutedEventArgs e)
    {
        if (PanelBlocked == null || PanelAllowed == null || PanelSubscriptions == null) return;

        PanelBlocked.Visibility = TabBlocked.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelAllowed.Visibility = TabAllowed.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        PanelSubscriptions.Visibility = TabSubscriptions.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    // --- Blocked Tab Actions ---

    private async void OnRemoveBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            await _sink.RemoveCustomRuleAsync(row.Domain);
            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Removed '{row.Domain}' from custom blocklist.";
        }
    }

    private async void OnMoveToAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            await _sink.AllowDomainAsync(row.Domain);
            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Moved '{row.Domain}' to custom whitelist.";
        }
    }

    private void OnLookupBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            OpenVirusTotal(row.Domain);
        }
    }

    private void OnCopyBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            CopyClipboard(row.Domain);
        }
    }

    private async void OnAddBlockClick(object sender, RoutedEventArgs e) => await AddBlockFromInputAsync();

    private async void OnNewBlockKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await AddBlockFromInputAsync();
    }

    private async Task AddBlockFromInputAsync()
    {
        string domain = NewBlockBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        await _sink.BlockDomainAsync(domain);
        NewBlockBox.Clear();
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Added '{domain}' to custom blocklist.";
    }

    // --- Allowed Tab Actions ---

    private async void OnRemoveAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            await _sink.RemoveCustomRuleAsync(row.Domain);
            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Removed '{row.Domain}' from whitelist.";
        }
    }

    private async void OnMoveToBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            await _sink.BlockDomainAsync(row.Domain);
            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Moved '{row.Domain}' to custom blocklist.";
        }
    }

    private void OnLookupAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            OpenVirusTotal(row.Domain);
        }
    }

    private void OnCopyAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            CopyClipboard(row.Domain);
        }
    }

    private async void OnAddAllowClick(object sender, RoutedEventArgs e) => await AddAllowFromInputAsync();

    private async void OnNewAllowKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await AddAllowFromInputAsync();
    }

    private async Task AddAllowFromInputAsync()
    {
        string domain = NewAllowBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        await _sink.AllowDomainAsync(domain);
        NewAllowBox.Clear();
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Added '{domain}' to whitelist.";
    }

    // --- Subscriptions Tab Actions ---

    private async void OnSubscribeClick(object sender, RoutedEventArgs e) => await SubscribeFromInputAsync();

    private async void OnNewListUrlKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await SubscribeFromInputAsync();
    }

    private async Task SubscribeFromInputAsync()
    {
        string url = NewListUrlBox.Text.Trim();
        string name = NewListNameBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(url)) return;

        DialogStatusText.Text = "Subscribing to blocklist and downloading domains...";
        try
        {
            await _sink.AddSubscriptionListAsync(name, url);
            NewListUrlBox.Clear();
            NewListNameBox.Clear();
            LoadSubscriptions();
            _onChanged();
            DialogStatusText.Text = $"Subscribed! Filter updated with {_sink.BlockedDomainCount:N0} total domains.";
        }
        catch (Exception ex)
        {
            DialogStatusText.Text = "Failed to add subscription: " + ex.Message;
        }
    }

    private async void OnRemoveSubscriptionClick(object sender, RoutedEventArgs e)
    {
        if (SubscriptionsGrid.SelectedItem is not SubscriptionRow row)
        {
            MessageBox.Show(this, "Please select a subscription list from the table to remove.", "Remove Blocklist", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var res = MessageBox.Show(this, $"Are you sure you want to unsubscribe and remove '{row.Name}'?\n\nURL: {row.Url}", "Confirm Unsubscribe", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (res != MessageBoxResult.Yes) return;

        DialogStatusText.Text = $"Removing '{row.Name}'...";
        try
        {
            await _sink.RemoveSubscriptionListAsync(row.Url);
            LoadSubscriptions();
            _onChanged();
            DialogStatusText.Text = $"Removed subscription '{row.Name}'. Total blocked domains: {_sink.BlockedDomainCount:N0}.";
        }
        catch (Exception ex)
        {
            DialogStatusText.Text = "Failed to remove subscription: " + ex.Message;
        }
    }

    private void OnOpenBlocklistsFolder(object sender, RoutedEventArgs e)
    {
        string dir = EngineStoragePaths.BlocklistsDirectory;
        try
        {
            if (Directory.Exists(dir))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
            }
        }
        catch { }
    }

    private async void OnUpdateAllListsClick(object sender, RoutedEventArgs e)
    {
        DialogStatusText.Text = "Downloading and updating subscription blocklists...";
        try
        {
            var results = await _sink.UpdateListsAsync();
            LoadSubscriptions();
            _onChanged();
            DialogStatusText.Text = $"Updated blocklists. {_sink.BlockedDomainCount:N0} domains currently blocked.";
        }
        catch (Exception ex)
        {
            DialogStatusText.Text = "Update failed: " + ex.Message;
        }
    }

    private void OpenVirusTotal(string domain)
    {
        string d = DomainFilter.Normalize(domain);
        if (string.IsNullOrWhiteSpace(d)) return;
        try
        {
            string url = $"https://www.virustotal.com/gui/domain/{Uri.EscapeDataString(d)}";
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
    }

    private void CopyClipboard(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        try
        {
            System.Windows.Clipboard.SetText(domain);
            DialogStatusText.Text = $"Copied '{domain}' to clipboard.";
        }
        catch { }
    }

    private async void OnImportBlocklistClick(object sender, RoutedEventArgs e)
    {
        bool isWhitelist = TabAllowed.IsChecked == true;
        string listTitle = isWhitelist ? "Custom Whitelist" : "Custom Blocklist";

        var ofd = new Microsoft.Win32.OpenFileDialog
        {
            Title = $"Import into {listTitle}",
            Filter = "All Supported Files (*.txt;*.hosts;hosts)|*.txt;*.hosts;hosts|Hosts Files (*.hosts;hosts)|*.hosts;hosts|Plain Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
            FilterIndex = 1,
            Multiselect = false
        };

        if (ofd.ShowDialog(this) != true) return;

        string filePath = ofd.FileName;
        if (!File.Exists(filePath)) return;

        DialogStatusText.Text = $"Importing rules from '{Path.GetFileName(filePath)}'...";
        try
        {
            var lines = await File.ReadAllLinesAsync(filePath);
            var (added, skipped) = await _sink.ImportCustomRulesAsync(lines, allow: isWhitelist);

            LoadData();
            _onChanged();

            string statusMsg = $"Imported {added:N0} new rules into {listTitle} ({skipped:N0} duplicates skipped).";
            DialogStatusText.Text = statusMsg;

            MessageBox.Show(this,
                $"Successfully imported {added:N0} rules into {listTitle}.\n\n" +
                $"• New rules added: {added:N0}\n" +
                $"• Duplicates/invalid skipped: {skipped:N0}\n" +
                $"• Source file: {Path.GetFileName(filePath)}",
                "Import Completed",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            DialogStatusText.Text = "Import failed: " + ex.Message;
            MessageBox.Show(this, $"Could not import list:\n{ex.Message}", "Import Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnExportBlocklistClick(object sender, RoutedEventArgs e)
    {
        var listToExport = TabAllowed.IsChecked == true
            ? _sink.Settings.CustomAllow
            : _sink.Settings.CustomBlock;

        string listName = TabAllowed.IsChecked == true ? "custom-allowlist" : "custom-blocklist";
        string listTitle = TabAllowed.IsChecked == true ? "Custom Whitelist" : "Custom Blocklist";

        if (listToExport.Count == 0)
        {
            MessageBox.Show(this, $"The {listTitle.ToLowerInvariant()} is currently empty. Add domains before exporting.", "Export Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var sfd = new Microsoft.Win32.SaveFileDialog
        {
            Title = $"Export {listTitle}",
            FileName = $"{listName}.txt",
            Filter = "Hosts File (*.txt)|*.txt|Plain Domain List (*.txt)|*.txt|All Files (*.*)|*.*",
            FilterIndex = 1,
            DefaultExt = ".txt"
        };

        if (sfd.ShowDialog(this) != true) return;

        try
        {
            var sb = new StringBuilder();
            if (sfd.FilterIndex == 1) // Hosts format: 0.0.0.0 domain
            {
                sb.AppendLine($"# SpectraNetworkManager {listTitle}");
                sb.AppendLine($"# Generated on: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"# Total domains: {listToExport.Count}");
                sb.AppendLine("# Format: 0.0.0.0 <domain>");
                sb.AppendLine();
                foreach (var domain in listToExport.OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine($"0.0.0.0 {domain}");
                }
            }
            else // Plain domain list
            {
                foreach (var domain in listToExport.OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine(domain);
                }
            }

            File.WriteAllText(sfd.FileName, sb.ToString());
            DialogStatusText.Text = $"Exported {listToExport.Count} domains to {Path.GetFileName(sfd.FileName)}.";
            MessageBox.Show(this, $"Successfully exported {listToExport.Count} domains to:\n{sfd.FileName}", "Export Completed", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Could not export rules: {ex.Message}", "Export Failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();
}
