using System.Windows;

namespace SpectraNetworkManager.Ui;

/// <summary>Explains strict mode and lets the user choose the two preparation steps. Cancel is the default button.</summary>
public partial class StrictDialog : Window
{
    public bool AllowRunning { get; private set; }
    public bool EnableAudit { get; private set; }

    public StrictDialog(Window owner, int runningCandidates, int existingAllowDecisions)
    {
        InitializeComponent();
        Owner = owner;
        AllowRunningText.Text =
            $"Allow all programs that are online right now ({runningCandidates} found; {existingAllowDecisions} programs are already allowed). " +
            "Recommended: otherwise your browser, mail and games stop working at once.";
    }

    private void OnEnable(object sender, RoutedEventArgs e)
    {
        AllowRunning = AllowRunningBox.IsChecked == true;
        EnableAudit = AuditBox.IsChecked == true;
        DialogResult = true;
    }
}
