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

    private readonly ICollectionView _blockedView;
    private readonly ICollectionView _allowedView;

    private bool IsTvMobileScope => ScopeTvMobileRadio?.IsChecked == true;
    private string ScopeDisplayName => IsTvMobileScope ? "Phone & TV" : "PC";

    public DnsCustomRulesWindow(DnsService sink, Action onChanged, bool openTvMobileScope = false)
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

        if (openTvMobileScope)
        {
            ScopeTvMobileRadio.IsChecked = true;
        }
        else
        {
            ScopePcRadio.IsChecked = true;
        }

        LoadData();
    }

    private void OnScopeChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        LoadData();
        DialogStatusText.Text = IsTvMobileScope
            ? $"Switched to Phone & Smart TV rules ({Path.GetFileName(_sink.TvMobileRulesFilePath)})."
            : $"Switched to PC rules ({Path.GetFileName(_sink.PcRulesFilePath)}).";
    }

    private void LoadData()
    {
        bool tvScope = IsTvMobileScope;
        var activeBlocked = tvScope ? _sink.TvMobileRules.CustomBlock : _sink.Settings.CustomBlock;
        var activeAllowed = tvScope ? _sink.TvMobileRules.CustomAllow : _sink.Settings.CustomAllow;

        _blocked.Clear();
        foreach (var rule in activeBlocked)
        {
            _blocked.Add(new CustomRuleRow(rule));
        }

        _allowed.Clear();
        foreach (var rule in activeAllowed)
        {
            _allowed.Add(new CustomRuleRow(rule));
        }

        int pcTotal = _sink.Settings.CustomBlock.Count + _sink.Settings.CustomAllow.Count;
        int tvTotal = _sink.TvMobileRules.CustomBlock.Count + _sink.TvMobileRules.CustomAllow.Count;

        if (ScopePcRadio != null)
            ScopePcRadio.Content = $"💻 PC Rules ({pcTotal:N0} in dns-settings.json)";
        if (ScopeTvMobileRadio != null)
            ScopeTvMobileRadio.Content = $"📱 Phone & Smart TV Rules ({tvTotal:N0} in tv-mobile-rules.json)";

        if (ActiveRuleFileText != null)
            ActiveRuleFileText.Text = tvScope ? _sink.TvMobileRulesFilePath : _sink.PcRulesFilePath;

        string targetLabel = tvScope ? "Phone & TV" : "PC";
        string otherLabel = tvScope ? "💻 Move Selected to PC List" : "📱 Move Selected to Phone & TV List";

        TabBlocked.Content = $"🚫 {targetLabel} Blocked ({_blocked.Count:N0})";
        TabAllowed.Content = $"🛡️ {targetLabel} Whitelist ({_allowed.Count:N0})";

        if (AddBlockBtn != null) AddBlockBtn.Content = $"+ Add to {targetLabel} Blocklist";
        if (AddAllowBtn != null) AddAllowBtn.Content = $"+ Add to {targetLabel} Whitelist";

        if (MoveScopeBlockedBtn != null) MoveScopeBlockedBtn.Content = otherLabel;
        if (MoveScopeBlockedMenuItem != null) MoveScopeBlockedMenuItem.Header = otherLabel;
        if (MoveScopeAllowedBtn != null) MoveScopeAllowedBtn.Content = otherLabel;
        if (MoveScopeAllowedMenuItem != null) MoveScopeAllowedMenuItem.Header = otherLabel;

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

        TabSubscriptions.Content = $"📁 Shared Subscription Lists ({_subscriptions.Count})";
        SubscriptionTotalText.Text = $"PC Blocked Domains: {_sink.BlockedDomainCount:N0}  •  Phone & TV Blocked Domains: {_sink.TvMobileBlockedDomainCount:N0}";
    }

    private void OnOpenActiveRuleFileFolderClick(object sender, RoutedEventArgs e)
    {
        string file = IsTvMobileScope ? _sink.TvMobileRulesFilePath : _sink.PcRulesFilePath;
        try
        {
            if (File.Exists(file))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{file}\"") { UseShellExecute = true });
            }
            else
            {
                string? dir = Path.GetDirectoryName(file);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
                }
            }
        }
        catch { }
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

    // --- Bulk & Multi-Selection Handlers (Blocked Grid) ---

    private async void OnMoveSelectedBlockedBetweenScopesClick(object sender, RoutedEventArgs e)
    {
        var selected = BlockedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Please select one or more blocked domains to move to the other list.", "Move Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        bool fromTvToPc = IsTvMobileScope;
        string destName = fromTvToPc ? "PC Blocklist (dns-settings.json)" : "Phone & TV Blocklist (tv-mobile-rules.json)";
        await _sink.MoveRulesBetweenScopesAsync(selected, fromTvMobileToPc: fromTvToPc, isAllowList: false, removeFromSource: true);
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Moved {selected.Count:N0} blocked rule(s) to {destName}.";
    }

    private async void OnRemoveSelectedBlockedClick(object sender, RoutedEventArgs e)
    {
        var selected = BlockedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Please select one or more rules to remove.", "Remove Selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string msg = selected.Count == 1
            ? $"Are you sure you want to remove '{selected[0]}' from your {ScopeDisplayName} custom blocklist?"
            : $"Are you sure you want to remove {selected.Count:N0} selected rules from your {ScopeDisplayName} custom blocklist?";

        if (MessageBox.Show(this, msg, "Confirm Remove Selected", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        if (IsTvMobileScope)
            await _sink.RemoveTvMobileCustomRulesBatchAsync(selected);
        else
            await _sink.RemoveCustomRulesBatchAsync(selected);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Removed {selected.Count:N0} rule(s) from {ScopeDisplayName} blocklist.";
    }

    private async void OnClearAllBlockedClick(object sender, RoutedEventArgs e)
    {
        int count = IsTvMobileScope ? _sink.TvMobileRules.CustomBlock.Count : _sink.Settings.CustomBlock.Count;
        if (count == 0)
        {
            MessageBox.Show(this, $"The {ScopeDisplayName} custom blocklist is already empty.", "Clear Blocklist", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show(this, $"Are you sure you want to delete ALL {count:N0} {ScopeDisplayName} custom blocked rules?\n\nThis action cannot be undone.", "Confirm Clear All", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        if (IsTvMobileScope)
            await _sink.ClearTvMobileCustomRulesAsync(allow: false);
        else
            await _sink.ClearCustomRulesAsync(allow: false);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Cleared all {count:N0} {ScopeDisplayName} custom blocked rules.";
    }

    private void OnBlockedGridKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete)
        {
            OnRemoveSelectedBlockedClick(sender, e);
            e.Handled = true;
        }
    }

    private async void OnMoveSelectedToAllowedClick(object sender, RoutedEventArgs e)
    {
        var selected = BlockedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0) return;

        if (IsTvMobileScope)
            await _sink.MoveTvMobileRulesAsync(selected, toAllow: true);
        else
            await _sink.MoveRulesAsync(selected, toAllow: true);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Moved {selected.Count:N0} rule(s) to {ScopeDisplayName} whitelist.";
    }

    private void OnWhoisBlockedContextItem(object sender, RoutedEventArgs e)
    {
        if (BlockedGrid.SelectedItem is CustomRuleRow row) OpenWhois(row.Domain);
    }

    private void OnWhoisBlockedItemButton(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row) OpenWhois(row.Domain);
    }

    private void OnLookupBlockedContextItem(object sender, RoutedEventArgs e)
    {
        if (BlockedGrid.SelectedItem is CustomRuleRow row) OpenVirusTotal(row.Domain);
    }

    private void OnCopyBlockedContextItem(object sender, RoutedEventArgs e)
    {
        var selected = BlockedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count > 0)
        {
            CopyClipboard(string.Join(Environment.NewLine, selected));
        }
    }

    // --- Blocked Tab Actions ---

    private async void OnRemoveBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            if (IsTvMobileScope)
                await _sink.RemoveTvMobileCustomRuleAsync(row.Domain);
            else
                await _sink.RemoveCustomRuleAsync(row.Domain);

            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Removed '{row.Domain}' from {ScopeDisplayName} blocklist.";
        }
    }

    private async void OnMoveToAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            if (IsTvMobileScope)
                await _sink.AllowTvMobileDomainAsync(row.Domain);
            else
                await _sink.AllowDomainAsync(row.Domain);

            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Moved '{row.Domain}' to {ScopeDisplayName} whitelist.";
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

    private async void OnNewBlockKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await AddBlockFromInputAsync();
    }

    private async Task AddBlockFromInputAsync()
    {
        string domain = NewBlockBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        if (IsTvMobileScope)
            await _sink.BlockTvMobileDomainAsync(domain);
        else
            await _sink.BlockDomainAsync(domain);

        NewBlockBox.Clear();
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Added '{domain}' to {ScopeDisplayName} custom blocklist.";
    }

    // --- Bulk & Multi-Selection Handlers (Allowed Grid) ---

    private async void OnMoveSelectedAllowedBetweenScopesClick(object sender, RoutedEventArgs e)
    {
        var selected = AllowedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Please select one or more whitelisted domains to move to the other list.", "Move Rules", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        bool fromTvToPc = IsTvMobileScope;
        string destName = fromTvToPc ? "PC Whitelist (dns-settings.json)" : "Phone & TV Whitelist (tv-mobile-rules.json)";
        await _sink.MoveRulesBetweenScopesAsync(selected, fromTvMobileToPc: fromTvToPc, isAllowList: true, removeFromSource: true);
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Moved {selected.Count:N0} whitelist rule(s) to {destName}.";
    }

    private async void OnRemoveSelectedAllowedClick(object sender, RoutedEventArgs e)
    {
        var selected = AllowedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Please select one or more rules to remove.", "Remove Selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string msg = selected.Count == 1
            ? $"Are you sure you want to remove '{selected[0]}' from your {ScopeDisplayName} whitelist?"
            : $"Are you sure you want to remove {selected.Count:N0} selected rules from your {ScopeDisplayName} whitelist?";

        if (MessageBox.Show(this, msg, "Confirm Remove Selected", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        if (IsTvMobileScope)
            await _sink.RemoveTvMobileCustomRulesBatchAsync(selected);
        else
            await _sink.RemoveCustomRulesBatchAsync(selected);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Removed {selected.Count:N0} rule(s) from {ScopeDisplayName} whitelist.";
    }

    private async void OnClearAllAllowedClick(object sender, RoutedEventArgs e)
    {
        int count = IsTvMobileScope ? _sink.TvMobileRules.CustomAllow.Count : _sink.Settings.CustomAllow.Count;
        if (count == 0)
        {
            MessageBox.Show(this, $"The {ScopeDisplayName} whitelist is already empty.", "Clear Whitelist", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show(this, $"Are you sure you want to delete ALL {count:N0} {ScopeDisplayName} whitelist rules?\n\nThis action cannot be undone.", "Confirm Clear All", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        if (IsTvMobileScope)
            await _sink.ClearTvMobileCustomRulesAsync(allow: true);
        else
            await _sink.ClearCustomRulesAsync(allow: true);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Cleared all {count:N0} {ScopeDisplayName} custom whitelist rules.";
    }

    private void OnAllowedGridKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete)
        {
            OnRemoveSelectedAllowedClick(sender, e);
            e.Handled = true;
        }
    }

    private async void OnMoveSelectedToBlockedClick(object sender, RoutedEventArgs e)
    {
        var selected = AllowedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count == 0) return;

        if (IsTvMobileScope)
            await _sink.MoveTvMobileRulesAsync(selected, toAllow: false);
        else
            await _sink.MoveRulesAsync(selected, toAllow: false);

        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Moved {selected.Count:N0} rule(s) to {ScopeDisplayName} custom blocklist.";
    }

    private void OnWhoisAllowedContextItem(object sender, RoutedEventArgs e)
    {
        if (AllowedGrid.SelectedItem is CustomRuleRow row) OpenWhois(row.Domain);
    }

    private void OnWhoisAllowedItemButton(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row) OpenWhois(row.Domain);
    }

    private void OnLookupAllowedContextItem(object sender, RoutedEventArgs e)
    {
        if (AllowedGrid.SelectedItem is CustomRuleRow row) OpenVirusTotal(row.Domain);
    }

    private void OnCopyAllowedContextItem(object sender, RoutedEventArgs e)
    {
        var selected = AllowedGrid.SelectedItems.OfType<CustomRuleRow>().Select(r => r.Domain).ToList();
        if (selected.Count > 0)
        {
            CopyClipboard(string.Join(Environment.NewLine, selected));
        }
    }

    // --- Allowed Tab Actions ---

    private async void OnRemoveAllowedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            if (IsTvMobileScope)
                await _sink.RemoveTvMobileCustomRuleAsync(row.Domain);
            else
                await _sink.RemoveCustomRuleAsync(row.Domain);

            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Removed '{row.Domain}' from {ScopeDisplayName} whitelist.";
        }
    }

    private async void OnMoveToBlockedItem(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.DataContext is CustomRuleRow row)
        {
            if (IsTvMobileScope)
                await _sink.BlockTvMobileDomainAsync(row.Domain);
            else
                await _sink.BlockDomainAsync(row.Domain);

            LoadData();
            _onChanged();
            DialogStatusText.Text = $"Moved '{row.Domain}' to {ScopeDisplayName} custom blocklist.";
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

    private async void OnNewAllowKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await AddAllowFromInputAsync();
    }

    private async Task AddAllowFromInputAsync()
    {
        string domain = NewAllowBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(domain)) return;

        if (IsTvMobileScope)
            await _sink.AllowTvMobileDomainAsync(domain);
        else
            await _sink.AllowDomainAsync(domain);

        NewAllowBox.Clear();
        LoadData();
        _onChanged();
        DialogStatusText.Text = $"Added '{domain}' to {ScopeDisplayName} whitelist.";
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

    private void OpenWhois(string domain)
    {
        string d = DomainFilter.Normalize(domain).TrimStart('*').TrimStart('.');
        if (string.IsNullOrWhiteSpace(d)) return;
        string root = DomainIntelligence.GetRootDomain(d);
        if (!string.IsNullOrWhiteSpace(root)) d = root;

        try
        {
            string url = $"https://who.is/whois/{Uri.EscapeDataString(d)}";
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
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
        string listTitle = $"{ScopeDisplayName} {(isWhitelist ? "Custom Whitelist" : "Custom Blocklist")}";

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
            var (added, skipped) = IsTvMobileScope
                ? await _sink.ImportTvMobileCustomRulesAsync(lines, allow: isWhitelist)
                : await _sink.ImportCustomRulesAsync(lines, allow: isWhitelist);

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
        bool isWhitelist = TabAllowed.IsChecked == true;
        var listToExport = IsTvMobileScope
            ? (isWhitelist ? _sink.TvMobileRules.CustomAllow : _sink.TvMobileRules.CustomBlock)
            : (isWhitelist ? _sink.Settings.CustomAllow : _sink.Settings.CustomBlock);

        string scopeSlug = IsTvMobileScope ? "phone-tv" : "pc";
        string listName = isWhitelist ? $"{scopeSlug}-custom-allowlist" : $"{scopeSlug}-custom-blocklist";
        string listTitle = $"{ScopeDisplayName} {(isWhitelist ? "Custom Whitelist" : "Custom Blocklist")}";

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
