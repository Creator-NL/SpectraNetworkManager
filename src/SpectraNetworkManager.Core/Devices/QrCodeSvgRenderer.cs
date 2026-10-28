using System;
using System.Collections.Generic;
using System.Text;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;
using ZXing.QrCode.Internal;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Robust, standard-compliant QR Code generator powered by ZXing.Net (from PrintSmartPro).
/// Generates full-fidelity QR codes with complete query parameters (?token=...) and error correction.
/// </summary>
public static class QrCodeSvgRenderer
{
    /// <summary>
    /// Generates an SVG string representation of a QR Code for the given text payload.
    /// </summary>
    public static string GenerateSvg(string text, int pixelSize = 240, string fgColor = "#00E5FF", string bgColor = "#0A0E17")
    {
        var (matrix, size, margin) = GenerateMatrix(text);
        int totalModules = size + (margin * 2);

        var sb = new StringBuilder();
        sb.AppendLine($"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {totalModules} {totalModules}\" width=\"{pixelSize}\" height=\"{pixelSize}\" shape-rendering=\"crispEdges\">");
        sb.AppendLine($"  <rect width=\"100%\" height=\"100%\" fill=\"{bgColor}\"/>");

        for (int r = 0; r < size; r++)
        {
            for (int c = 0; c < size; c++)
            {
                if (matrix[r, c])
                {
                    sb.AppendLine($"  <rect x=\"{c + margin}\" y=\"{r + margin}\" width=\"1\" height=\"1\" fill=\"{fgColor}\"/>");
                }
            }
        }

        sb.AppendLine("</svg>");
        return sb.ToString();
    }

    /// <summary>
    /// Generates the raw boolean module matrix for the QR Code (true = dark module, false = light module).
    /// </summary>
    public static (bool[,] Matrix, int Size, int Margin) GenerateMatrix(string text)
    {
        if (string.IsNullOrEmpty(text)) text = " ";

        var writer = new QRCodeWriter();
        var hints = new Dictionary<EncodeHintType, object>
        {
            { EncodeHintType.CHARACTER_SET, "UTF-8" },
            { EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M },
            { EncodeHintType.MARGIN, 0 }
        };

        BitMatrix bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, 0, 0, hints);
        int size = bitMatrix.Width;
        bool[,] matrix = new bool[size, size];

        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                matrix[y, x] = bitMatrix[x, y];
            }
        }

        return (matrix, size, 2);
    }
}
