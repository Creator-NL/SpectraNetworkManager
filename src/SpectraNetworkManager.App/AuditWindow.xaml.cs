using System.Text;
using System.Windows;
using SpectraNetworkManager.Core.Audit;

namespace SpectraNetworkManager.Ui;

public partial class AuditWindow : Window
{
    private readonly Func<SystemAuditReport> _auditProvider;
    private readonly Action<AuditFinding> _fixHandler;
    private SystemAuditReport? _currentReport;

    public string? SelectedTargetTab { get; private set; }

    public AuditWindow(Func<SystemAuditReport> auditProvider, Action<AuditFinding> fixHandler)
    {
        InitializeComponent();
        _auditProvider = auditProvider;
        _fixHandler = fixHandler;
        Loaded += (_, _) => RunAudit();
    }

    public void RunAudit()
    {
        _currentReport = _auditProvider();
        AuditScoreText.Text = _currentReport.HealthScore.ToString();
        AuditRatingText.Text = _currentReport.HealthRating;
        AuditPassedCountText.Text = _currentReport.GoodCount.ToString();
        AuditWarningCountText.Text = _currentReport.WarningCount.ToString();
        AuditCriticalCountText.Text = _currentReport.CriticalCount.ToString();
        AuditTimestampText.Text = $"Audit run at {_currentReport.AuditTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";

        FindingsList.ItemsSource = _currentReport.Findings;
    }

    private void OnFindingActionClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is AuditFinding finding)
        {
            if (finding.CanAutoFix)
            {
                _fixHandler(finding);
                RunAudit();
            }
            else if (!string.IsNullOrEmpty(finding.TargetTab))
            {
                SelectedTargetTab = finding.TargetTab;
                DialogResult = true;
                Close();
            }
        }
    }

    private void OnRerunAuditClick(object sender, RoutedEventArgs e)
    {
        RunAudit();
    }

    private void OnCopyReportClick(object sender, RoutedEventArgs e)
    {
        if (_currentReport == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"=== SPECTRA NETWORK MANAGER v2.0 - SYSTEM AUDIT REPORT ===");
        sb.AppendLine($"Audit Time: {_currentReport.AuditTimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Health Score: {_currentReport.HealthScore}/100 ({_currentReport.HealthRating})");
        sb.AppendLine($"Passed: {_currentReport.GoodCount} | Warnings: {_currentReport.WarningCount} | Critical: {_currentReport.CriticalCount}");
        sb.AppendLine();
        foreach (var f in _currentReport.Findings)
        {
            sb.AppendLine($"[{f.SeverityBadge}] {f.Category.ToUpperInvariant()}: {f.Title}");
            sb.AppendLine($"  {f.Description}");
            if (!string.IsNullOrEmpty(f.Recommendation))
            {
                sb.AppendLine($"  Fix: {f.Recommendation}");
            }
            sb.AppendLine();
        }

        try { System.Windows.Clipboard.SetText(sb.ToString()); } catch { }
        MessageBox.Show(this, "Audit findings copied to clipboard!", "Report Copied", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
