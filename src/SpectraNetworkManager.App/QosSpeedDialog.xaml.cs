using System.IO;
using System.Windows;

namespace SpectraNetworkManager.Ui;

public partial class QosSpeedDialog : Window
{
    private readonly string _exePath;
    public long SelectedBitsPerSec { get; private set; }

    public QosSpeedDialog(string exePath, long currentBitsPerSec)
    {
        InitializeComponent();
        _exePath = exePath;
        TargetProgramText.Text = $"Target: {Path.GetFileName(exePath)} ({exePath})";

        if (currentBitsPerSec <= 0)
        {
            OptNoLimit.IsChecked = true;
            CurrentLimitNoticeText.Text = "Currently: Unrestricted";
        }
        else
        {
            CurrentLimitNoticeText.Text = $"Currently: {FormatRate(currentBitsPerSec)}";
            switch (currentBitsPerSec)
            {
                case 256_000: Opt256k.IsChecked = true; break;
                case 512_000: Opt512k.IsChecked = true; break;
                case 1_000_000: Opt1M.IsChecked = true; break;
                case 2_000_000: Opt2M.IsChecked = true; break;
                case 5_000_000: Opt5M.IsChecked = true; break;
                case 10_000_000: Opt10M.IsChecked = true; break;
                default:
                    OptCustom.IsChecked = true;
                    if (currentBitsPerSec >= 1_000_000)
                    {
                        CustomSpeedBox.Text = (currentBitsPerSec / 1_000_000.0).ToString("F0");
                        CustomUnitCombo.SelectedIndex = 1;
                    }
                    else
                    {
                        CustomSpeedBox.Text = (currentBitsPerSec / 1_000.0).ToString("F0");
                        CustomUnitCombo.SelectedIndex = 0;
                    }
                    break;
            }
        }
    }

    private void OnApplyClick(object sender, RoutedEventArgs e)
    {
        if (OptNoLimit.IsChecked == true)
        {
            SelectedBitsPerSec = 0;
        }
        else if (Opt256k.IsChecked == true)
        {
            SelectedBitsPerSec = 256_000;
        }
        else if (Opt512k.IsChecked == true)
        {
            SelectedBitsPerSec = 512_000;
        }
        else if (Opt1M.IsChecked == true)
        {
            SelectedBitsPerSec = 1_000_000;
        }
        else if (Opt2M.IsChecked == true)
        {
            SelectedBitsPerSec = 2_000_000;
        }
        else if (Opt5M.IsChecked == true)
        {
            SelectedBitsPerSec = 5_000_000;
        }
        else if (Opt10M.IsChecked == true)
        {
            SelectedBitsPerSec = 10_000_000;
        }
        else if (OptCustom.IsChecked == true)
        {
            if (!double.TryParse(CustomSpeedBox.Text.Trim(), out double val) || val <= 0)
            {
                MessageBox.Show(this, "Please enter a valid positive number for the custom speed.", "Invalid Speed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            bool isMbps = CustomUnitCombo.SelectedIndex == 1;
            SelectedBitsPerSec = (long)(val * (isMbps ? 1_000_000 : 1_000));
        }

        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private static string FormatRate(long bitsPerSec) => bitsPerSec switch
    {
        >= 1_000_000_000 => $"{bitsPerSec / 1_000_000_000.0:F1} Gbps",
        >= 1_000_000 => $"{bitsPerSec / 1_000_000.0:F1} Mbps",
        >= 1_000 => $"{bitsPerSec / 1_000.0:F0} Kbps",
        _ => $"{bitsPerSec} bps"
    };
}
