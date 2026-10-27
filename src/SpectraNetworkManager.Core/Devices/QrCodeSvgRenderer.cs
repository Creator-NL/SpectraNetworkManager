using System;
using System.Collections.Generic;
using System.Text;

namespace SpectraNetworkManager.Core.Devices;

/// <summary>
/// Standalone, pure C# QR Code generator that emits scalable SVG vector images.
/// Requires zero third-party packages or native binaries. Supports Version 1-4 (up to 78 alphanumeric chars).
/// </summary>
public static class QrCodeSvgRenderer
{
    // GF(256) logarithm and exponent tables for Reed-Solomon calculations
    private static readonly byte[] ExpTable = new byte[512];
    private static readonly byte[] LogTable = new byte[256];

    static QrCodeSvgRenderer()
    {
        int val = 1;
        for (int i = 0; i < 255; i++)
        {
            ExpTable[i] = (byte)val;
            ExpTable[i + 255] = (byte)val;
            LogTable[val] = (byte)i;
            val <<= 1;
            if ((val & 0x100) != 0) val ^= 0x11D;
        }
    }

    private static byte GfMultiply(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        return ExpTable[LogTable[a] + LogTable[b]];
    }

    private static byte[] GenerateRsCoefficients(int ecCount)
    {
        var poly = new byte[] { 1 };
        for (int i = 0; i < ecCount; i++)
        {
            var next = new byte[poly.Length + 1];
            byte factor = ExpTable[i];
            for (int j = 0; j < poly.Length; j++)
            {
                next[j] ^= GfMultiply(poly[j], factor);
                next[j + 1] ^= poly[j];
            }
            poly = next;
        }
        return poly;
    }

    private static byte[] CalculateEcc(byte[] data, int ecCount)
    {
        var generator = GenerateRsCoefficients(ecCount);
        var remainder = new byte[ecCount];

        foreach (byte b in data)
        {
            byte factor = (byte)(b ^ remainder[0]);
            Array.Copy(remainder, 1, remainder, 0, ecCount - 1);
            remainder[ecCount - 1] = 0;
            for (int j = 0; j < ecCount; j++)
            {
                remainder[j] ^= GfMultiply(generator[j], factor);
            }
        }
        return remainder;
    }

    /// <summary>
    /// Generates an SVG string representation of a QR Code for the given text payload.
    /// </summary>
    public static string GenerateSvg(string text, int pixelSize = 240, string fgColor = "#00E5FF", string bgColor = "#0A0E17")
    {
        if (string.IsNullOrEmpty(text)) text = " ";
        byte[] textBytes = Encoding.UTF8.GetBytes(text);

        // Version selection: V1 (17 data bytes, 7 EC), V2 (32 data bytes, 10 EC), V3 (53 data bytes, 15 EC), V4 (78 data bytes, 20 EC)
        int version;
        int totalDataBytes;
        int ecBytes;
        int size;

        if (textBytes.Length <= 14)
        {
            version = 1;
            totalDataBytes = 19;
            ecBytes = 7;
            size = 21;
        }
        else if (textBytes.Length <= 29)
        {
            version = 2;
            totalDataBytes = 34;
            ecBytes = 10;
            size = 25;
        }
        else if (textBytes.Length <= 50)
        {
            version = 3;
            totalDataBytes = 55;
            ecBytes = 15;
            size = 29;
        }
        else
        {
            version = 4;
            totalDataBytes = 80;
            ecBytes = 20;
            size = 33;
        }

        // Build data bit stream (Byte Mode: 0100)
        var bitList = new List<bool>();
        void AppendBits(int value, int count)
        {
            for (int i = count - 1; i >= 0; i--)
                bitList.Add(((value >> i) & 1) == 1);
        }

        AppendBits(0b0100, 4); // Byte mode indicator
        AppendBits(textBytes.Length, 8); // Character count
        foreach (byte b in textBytes) AppendBits(b, 8);
        AppendBits(0, Math.Min(4, (totalDataBytes * 8) - bitList.Count)); // Terminator

        while (bitList.Count % 8 != 0) bitList.Add(false);

        // Convert bits to bytes
        var dataBytes = new byte[totalDataBytes];
        for (int i = 0; i < bitList.Count / 8 && i < totalDataBytes; i++)
        {
            int val = 0;
            for (int b = 0; b < 8; b++)
                if (bitList[(i * 8) + b]) val |= (1 << (7 - b));
            dataBytes[i] = (byte)val;
        }

        // Pad bytes
        int padIdx = bitList.Count / 8;
        byte[] padPatterns = { 0xEC, 0x11 };
        int padToggle = 0;
        while (padIdx < totalDataBytes)
        {
            dataBytes[padIdx++] = padPatterns[padToggle];
            padToggle ^= 1;
        }

        // Calculate Reed-Solomon Error Correction Codewords
        byte[] ecc = CalculateEcc(dataBytes, ecBytes);

        // Matrix allocation
        bool[,] matrix = new bool[size, size];
        bool[,] isFunction = new bool[size, size];

        void SetFunction(int r, int c, bool val)
        {
            if (r >= 0 && r < size && c >= 0 && c < size)
            {
                matrix[r, c] = val;
                isFunction[r, c] = true;
            }
        }

        // 1. Finder patterns (7x7) + Separators
        void PlaceFinder(int row, int col)
        {
            for (int r = -1; r <= 7; r++)
            {
                for (int c = -1; c <= 7; c++)
                {
                    int mr = row + r;
                    int mc = col + c;
                    if (mr < 0 || mr >= size || mc < 0 || mc >= size) continue;

                    bool isBorder = (r == 0 || r == 6 || c == 0 || c == 6) && (r >= 0 && r <= 6 && c >= 0 && c <= 6);
                    bool isCenter = (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                    SetFunction(mr, mc, isBorder || isCenter);
                }
            }
        }

        PlaceFinder(0, 0);
        PlaceFinder(0, size - 7);
        PlaceFinder(size - 7, 0);

        // 2. Alignment pattern for Version >= 2
        if (version >= 2)
        {
            int align = size - 7;
            for (int r = -2; r <= 2; r++)
            {
                for (int c = -2; c <= 2; c++)
                {
                    bool isEdge = (Math.Abs(r) == 2 || Math.Abs(c) == 2);
                    bool isDot = (r == 0 && c == 0);
                    SetFunction(align + r, align + c, isEdge || isDot);
                }
            }
        }

        // 3. Timing patterns
        for (int i = 8; i < size - 8; i++)
        {
            SetFunction(6, i, i % 2 == 0);
            SetFunction(i, 6, i % 2 == 0);
        }

        // 4. Dark module
        SetFunction((4 * version) + 9, 8, true);

        // Reserve format info areas
        for (int i = 0; i < 9; i++)
        {
            if (!isFunction[8, i]) SetFunction(8, i, false);
            if (!isFunction[i, 8]) SetFunction(i, 8, false);
        }
        for (int i = 0; i < 8; i++)
        {
            if (!isFunction[8, size - 1 - i]) SetFunction(8, size - 1 - i, false);
            if (!isFunction[size - 1 - i, 8]) SetFunction(size - 1 - i, 8, false);
        }

        // 5. Interleave all data and EC bits
        var allBits = new List<bool>();
        foreach (byte b in dataBytes)
            for (int i = 7; i >= 0; i--) allBits.Add(((b >> i) & 1) == 1);
        foreach (byte b in ecc)
            for (int i = 7; i >= 0; i--) allBits.Add(((b >> i) & 1) == 1);

        // 6. Place data bits in matrix (serpentine upwards/downwards)
        int bitIdx = 0;
        int right = size - 1;
        while (right > 0)
        {
            if (right == 6) right--; // Skip vertical timing pattern
            for (int vert = 0; vert < size; vert++)
            {
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j;
                    bool upwards = ((right + 1) & 2) == 0;
                    int y = upwards ? (size - 1 - vert) : vert;

                    if (!isFunction[y, x])
                    {
                        bool bit = bitIdx < allBits.Count ? allBits[bitIdx++] : false;
                        // Apply Mask 0: (row + col) % 2 == 0
                        bool mask = ((y + x) % 2) == 0;
                        matrix[y, x] = bit ^ mask;
                    }
                }
            }
            right -= 2;
        }

        // 7. Write Format Information (Error Correction Level L = 01, Mask 0 = 000 -> 0x4E7B with mask 0x5412)
        int formatBits = 0x4E7B ^ 0x5412;
        for (int i = 0; i < 15; i++)
        {
            bool bit = ((formatBits >> i) & 1) == 1;
            // Top-left format info
            if (i <= 5) matrix[8, i] = bit;
            else if (i == 6) matrix[8, 7] = bit;
            else if (i == 7) matrix[8, 8] = bit;
            else if (i == 8) matrix[7, 8] = bit;
            else matrix[14 - i, 8] = bit;

            // Split format info around edges
            if (i < 8) matrix[size - 1 - i, 8] = bit;
            else matrix[8, size - 15 + i] = bit;
        }

        // 8. Render to SVG
        int margin = 2;
        int totalModules = size + (margin * 2);
        double scale = (double)pixelSize / totalModules;

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
        byte[] textBytes = Encoding.UTF8.GetBytes(text);

        int version;
        int totalDataBytes;
        int ecBytes;
        int size;

        if (textBytes.Length <= 14)
        {
            version = 1;
            totalDataBytes = 19;
            ecBytes = 7;
            size = 21;
        }
        else if (textBytes.Length <= 29)
        {
            version = 2;
            totalDataBytes = 34;
            ecBytes = 10;
            size = 25;
        }
        else if (textBytes.Length <= 50)
        {
            version = 3;
            totalDataBytes = 55;
            ecBytes = 15;
            size = 29;
        }
        else
        {
            version = 4;
            totalDataBytes = 80;
            ecBytes = 20;
            size = 33;
        }

        var bitList = new List<bool>();
        void AppendBits(int value, int count)
        {
            for (int i = count - 1; i >= 0; i--)
                bitList.Add(((value >> i) & 1) == 1);
        }

        AppendBits(0b0100, 4);
        AppendBits(textBytes.Length, 8);
        foreach (byte b in textBytes) AppendBits(b, 8);
        AppendBits(0, Math.Min(4, (totalDataBytes * 8) - bitList.Count));

        while (bitList.Count % 8 != 0) bitList.Add(false);

        var dataBytes = new byte[totalDataBytes];
        for (int i = 0; i < bitList.Count / 8 && i < totalDataBytes; i++)
        {
            int val = 0;
            for (int b = 0; b < 8; b++)
                if (bitList[(i * 8) + b]) val |= (1 << (7 - b));
            dataBytes[i] = (byte)val;
        }

        int padIdx = bitList.Count / 8;
        byte[] padPatterns = { 0xEC, 0x11 };
        int padToggle = 0;
        while (padIdx < totalDataBytes)
        {
            dataBytes[padIdx++] = padPatterns[padToggle];
            padToggle ^= 1;
        }

        byte[] ecc = CalculateEcc(dataBytes, ecBytes);

        bool[,] matrix = new bool[size, size];
        bool[,] isFunction = new bool[size, size];

        void SetFunction(int r, int c, bool val)
        {
            if (r >= 0 && r < size && c >= 0 && c < size)
            {
                matrix[r, c] = val;
                isFunction[r, c] = true;
            }
        }

        void PlaceFinder(int row, int col)
        {
            for (int r = -1; r <= 7; r++)
            {
                for (int c = -1; c <= 7; c++)
                {
                    int mr = row + r;
                    int mc = col + c;
                    if (mr < 0 || mr >= size || mc < 0 || mc >= size) continue;

                    bool isBorder = (r == 0 || r == 6 || c == 0 || c == 6) && (r >= 0 && r <= 6 && c >= 0 && c <= 6);
                    bool isCenter = (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                    SetFunction(mr, mc, isBorder || isCenter);
                }
            }
        }

        PlaceFinder(0, 0);
        PlaceFinder(0, size - 7);
        PlaceFinder(size - 7, 0);

        if (version >= 2)
        {
            int align = size - 7;
            for (int r = -2; r <= 2; r++)
            {
                for (int c = -2; c <= 2; c++)
                {
                    bool isEdge = (Math.Abs(r) == 2 || Math.Abs(c) == 2);
                    bool isDot = (r == 0 && c == 0);
                    SetFunction(align + r, align + c, isEdge || isDot);
                }
            }
        }

        for (int i = 8; i < size - 8; i++)
        {
            SetFunction(6, i, i % 2 == 0);
            SetFunction(i, 6, i % 2 == 0);
        }

        SetFunction((4 * version) + 9, 8, true);

        for (int i = 0; i < 9; i++)
        {
            if (!isFunction[8, i]) SetFunction(8, i, false);
            if (!isFunction[i, 8]) SetFunction(i, 8, false);
        }
        for (int i = 0; i < 8; i++)
        {
            if (!isFunction[8, size - 1 - i]) SetFunction(8, size - 1 - i, false);
            if (!isFunction[size - 1 - i, 8]) SetFunction(size - 1 - i, 8, false);
        }

        var allBits = new List<bool>();
        foreach (byte b in dataBytes)
            for (int i = 7; i >= 0; i--) allBits.Add(((b >> i) & 1) == 1);
        foreach (byte b in ecc)
            for (int i = 7; i >= 0; i--) allBits.Add(((b >> i) & 1) == 1);

        int bitIdx = 0;
        int right = size - 1;
        while (right > 0)
        {
            if (right == 6) right--;
            for (int vert = 0; vert < size; vert++)
            {
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j;
                    bool upwards = ((right + 1) & 2) == 0;
                    int y = upwards ? (size - 1 - vert) : vert;

                    if (!isFunction[y, x])
                    {
                        bool bit = bitIdx < allBits.Count ? allBits[bitIdx++] : false;
                        bool mask = ((y + x) % 2) == 0;
                        matrix[y, x] = bit ^ mask;
                    }
                }
            }
            right -= 2;
        }

        int formatBits = 0x4E7B ^ 0x5412;
        for (int i = 0; i < 15; i++)
        {
            bool bit = ((formatBits >> i) & 1) == 1;
            if (i <= 5) matrix[8, i] = bit;
            else if (i == 6) matrix[8, 7] = bit;
            else if (i == 7) matrix[8, 8] = bit;
            else if (i == 8) matrix[7, 8] = bit;
            else matrix[14 - i, 8] = bit;

            if (i < 8) matrix[size - 1 - i, 8] = bit;
            else matrix[8, size - 15 + i] = bit;
        }

        return (matrix, size, 2);
    }
}
