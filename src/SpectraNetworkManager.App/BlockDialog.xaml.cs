using System.Windows;
using SpectraNetworkManager.Core;

namespace SpectraNetworkManager.Ui;

/// <summary>
/// Asks how to block a program: direction, and either everything or only specific traffic (protocol, ports, addresses),
/// or the reverse ("allow only this"). Cancel is the default button on purpose.
/// </summary>
public partial class BlockDialog : Window
{
    private readonly bool _ready;

    public RuleDirection Direction { get; private set; } = RuleDirection.Both;
    public TrafficScope Scope { get; private set; } = TrafficScope.All;

    public BlockDialog(Window owner, string programName, string path, ProgramRule? existing = null)
    {
        InitializeComponent();
        Owner = owner;
        Heading.Text = existing is { Action: RuleAction.Block } ? $"Change the block for {programName}" : $"Block {programName}?";
        PathText.Text = path;

        if (existing is { Action: RuleAction.Block } rule)
        {
            OutRadio.IsChecked = rule.Direction == RuleDirection.Outbound;
            InRadio.IsChecked = rule.Direction == RuleDirection.Inbound;
            BothRadio.IsChecked = rule.Direction == RuleDirection.Both;

            var scope = rule.EffectiveScope;
            ModeAll.IsChecked = scope.Mode == ScopeMode.Everything;
            ModeMatching.IsChecked = scope.Mode == ScopeMode.BlockMatching;
            ModeAllowOnly.IsChecked = scope.Mode == ScopeMode.AllowOnly;
            ProtoAny.IsChecked = scope.Protocol == TrafficProtocol.Any;
            ProtoTcp.IsChecked = scope.Protocol == TrafficProtocol.Tcp;
            ProtoUdp.IsChecked = scope.Protocol == TrafficProtocol.Udp;
            PortsBox.Text = scope.Ports;
            AddressesBox.Text = scope.Addresses;
            KeepLanBox.IsChecked = scope.KeepLocalNetwork;
        }

        _ready = true;
        Revalidate();
    }

    // Change handlers fire while the XAML loads; ignore them until the dialog is fully built.
    private void OnInputChanged(object sender, RoutedEventArgs e)
    {
        if (_ready) Revalidate();
    }

    private void Revalidate()
    {
        Conditions.IsEnabled = ModeAll.IsChecked != true;

        Direction = OutRadio.IsChecked == true ? RuleDirection.Outbound
                  : InRadio.IsChecked == true ? RuleDirection.Inbound
                  : RuleDirection.Both;

        Scope = new TrafficScope(
            Mode: ModeAllowOnly.IsChecked == true ? ScopeMode.AllowOnly
                : ModeMatching.IsChecked == true ? ScopeMode.BlockMatching
                : ScopeMode.Everything,
            Protocol: ProtoTcp.IsChecked == true ? TrafficProtocol.Tcp
                    : ProtoUdp.IsChecked == true ? TrafficProtocol.Udp
                    : TrafficProtocol.Any,
            Ports: PortsBox.Text.Trim(),
            Addresses: AddressesBox.Text.Trim(),
            KeepLocalNetwork: KeepLanBox.IsChecked == true && ModeAllowOnly.IsChecked == true);

        KeepLanBox.IsEnabled = ModeAllowOnly.IsChecked == true;

        if (!Scope.TryValidate(out string error))
        {
            ErrorText.Text = error;
            SummaryText.Text = "";
            BlockButton.IsEnabled = false;
            return;
        }

        try
        {
            int rules = RulePlanner.Plan(Direction, Scope).Count;
            if (rules == 0)
            {
                ErrorText.Text = "With these settings nothing would be blocked.";
                SummaryText.Text = "";
                BlockButton.IsEnabled = false;
                return;
            }

            ErrorText.Text = "";
            SummaryText.Text = $"Blocks: {Scope.Describe()}, {DescribeDirection(Direction)}.  This creates {rules} Windows Firewall rule{(rules == 1 ? "" : "s")}.";
            BlockButton.IsEnabled = true;
        }
        catch (ArgumentException ex)
        {
            ErrorText.Text = ex.Message;
            SummaryText.Text = "";
            BlockButton.IsEnabled = false;
        }
    }

    private static string DescribeDirection(RuleDirection d) => d switch
    {
        RuleDirection.Outbound => "outgoing traffic",
        RuleDirection.Inbound => "incoming traffic",
        _ => "incoming and outgoing traffic",
    };

    private void OnBlock(object sender, RoutedEventArgs e) => DialogResult = true;
}
