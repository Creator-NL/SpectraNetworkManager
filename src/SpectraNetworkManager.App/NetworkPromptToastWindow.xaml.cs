using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Ui;

public partial class NetworkPromptToastWindow : Window
{
    private ProgramSummary? _currentProgram;
    private ProgramStanding? _currentStanding;

    public event Action<ProgramSummary>? AllowRequested;
    public event Action<ProgramSummary>? BlockRequested;
    public event Action<ProgramSummary>? TrustRequested;
    public event Action<ProgramSummary>? LaterRequested;
    public event Action<ProgramSummary>? InspectRequested;

    public NetworkPromptToastWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        SourceInitialized += OnSourceInitialized;
        SizeChanged += (_, _) => Reposition();
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var handle = new WindowInteropHelper(this).Handle;
        NativeMethods.SetNoActivate(handle);
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        Reposition();
    }

    public void Reposition()
    {
        var workArea = SystemParameters.WorkArea;
        Left = Math.Max(0, workArea.Right - ActualWidth - 16);
        Top = Math.Max(0, workArea.Bottom - ActualHeight - 16);
    }

    public void DisplayPrompt(ProgramSummary program, ProgramStanding standing, string destination, int queueCount)
    {
        _currentProgram = program;
        _currentStanding = standing;

        ProgramNameText.Text = program.Name;
        ProgramPathText.Text = program.Path ?? "(Unknown path)";
        DestinationText.Text = string.IsNullOrWhiteSpace(destination) ? "(No internet connection right now)" : destination;

        string signerDesc = standing.Signature?.Describe() ?? "Unknown / Not signed";
        SignerText.Text = signerDesc;

        bool isAlarming = standing.Signature is { IsAlarming: true };
        WarningText.Visibility = isAlarming ? Visibility.Visible : Visibility.Collapsed;

        if (queueCount > 0)
        {
            QueueText.Text = $"+{queueCount} waiting";
            QueueBadge.Visibility = Visibility.Visible;
        }
        else
        {
            QueueBadge.Visibility = Visibility.Collapsed;
        }

        bool canTrust = standing.Signature is { Status: SignatureStatus.Valid, Publisher: not null } && !standing.PublisherTrusted;
        if (canTrust)
        {
            TrustButton.Content = $"Trust {standing.Signature!.Publisher}";
            TrustButton.Visibility = Visibility.Visible;
        }
        else
        {
            TrustButton.Visibility = Visibility.Collapsed;
        }

        if (Visibility != Visibility.Visible)
        {
            Show();
        }
        Reposition();
    }

    private void OnAllowClick(object sender, RoutedEventArgs e)
    {
        if (_currentProgram != null)
        {
            AllowRequested?.Invoke(_currentProgram);
        }
    }

    private void OnBlockClick(object sender, RoutedEventArgs e)
    {
        if (_currentProgram != null)
        {
            BlockRequested?.Invoke(_currentProgram);
        }
    }

    private void OnTrustClick(object sender, RoutedEventArgs e)
    {
        if (_currentProgram != null)
        {
            TrustRequested?.Invoke(_currentProgram);
        }
    }

    private void OnLaterClick(object sender, RoutedEventArgs e)
    {
        if (_currentProgram != null)
        {
            LaterRequested?.Invoke(_currentProgram);
        }
    }

    private void OnPromptMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2 && _currentProgram != null)
        {
            e.Handled = true;
            InspectRequested?.Invoke(_currentProgram);
        }
    }
}
