using NetSentinel.Core;
using Xunit;

namespace NetSentinel.Platform.Windows.Tests;

public class NativeSignatureTests
{
    [Fact]
    public void VerifyFile_Notepad_ReturnsValidAndOsBinary()
    {
        string notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(notepadPath))
        {
            notepadPath = @"C:\Windows\notepad.exe";
        }

        var result = NativeAuthenticodeVerifier.VerifyFile(notepadPath);

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.NotNull(result.Publisher);
        Assert.Contains("Microsoft", result.Publisher);
        Assert.True(result.IsOsBinary);
    }

    [Fact]
    public void VerifyFile_Svchost_ReturnsValidCatalogOrEmbedded()
    {
        string svchostPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe");
        if (File.Exists(svchostPath))
        {
            var result = NativeAuthenticodeVerifier.VerifyFile(svchostPath);

            Assert.Equal(SignatureStatus.Valid, result.Status);
            Assert.NotNull(result.Publisher);
            Assert.Contains("Microsoft", result.Publisher);
            Assert.True(result.IsOsBinary);
        }
    }

    [Fact]
    public void VerifyFile_NonExistentFile_ReturnsUnknown()
    {
        var result = NativeAuthenticodeVerifier.VerifyFile(@"C:\NonExistent_Fake_Binary_12345.exe");

        Assert.Equal(SignatureStatus.Unknown, result.Status);
        Assert.Equal("file not found", result.Detail);
    }

    [Fact]
    public void VerifyFile_UnsignedTextFile_ReturnsNotSigned()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "not an executable or signed binary");
            var result = NativeAuthenticodeVerifier.VerifyFile(tempFile);

            Assert.Equal(SignatureStatus.NotSigned, result.Status);
            Assert.False(result.IsOsBinary);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }
}
