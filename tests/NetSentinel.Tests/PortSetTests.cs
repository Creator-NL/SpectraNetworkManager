using NetSentinel.Core;

namespace NetSentinel.Tests;

public class PortSetTests
{
    [Fact]
    public void Empty_ContainsNoPorts()
    {
        var set = PortSet.Empty;
        Assert.True(set.IsEmpty);
        Assert.False(set.Contains(80));
        Assert.False(set.Contains(443));
    }

    [Fact]
    public void ComplementOfEmpty_ContainsAllPorts()
    {
        var all = PortSet.Empty.Complement();
        Assert.False(all.IsEmpty);
        Assert.True(all.Contains(1));
        Assert.True(all.Contains(80));
        Assert.True(all.Contains(443));
        Assert.True(all.Contains(65535));
    }

    [Theory]
    [InlineData("80", new[] { 80 }, new[] { 79, 81, 443 })]
    [InlineData("80, 443", new[] { 80, 443 }, new[] { 81, 8080 })]
    [InlineData("1000-2000", new[] { 1000, 1500, 2000 }, new[] { 999, 2001 })]
    [InlineData("80, 100-200, 150-250", new[] { 80, 100, 200, 250 }, new[] { 81, 99, 251 })]
    public void TryParse_ValidInput_ContainsExpectedPorts(string text, int[] expectedInside, int[] expectedOutside)
    {
        Assert.True(PortSet.TryParse(text, out var set, out var err), err);
        Assert.NotNull(set);
        foreach (int p in expectedInside) Assert.True(set.Contains(p), $"Port {p} should be inside {text}");
        foreach (int p in expectedOutside) Assert.False(set.Contains(p), $"Port {p} should be outside {text}");
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("abc")]
    [InlineData("80-")]
    [InlineData("500-100")]
    public void TryParse_InvalidInput_ReturnsFalse(string text)
    {
        Assert.False(PortSet.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Complement_OfEmpty_ContainsAll()
    {
        var comp = PortSet.Empty.Complement();
        Assert.True(comp.Contains(1));
        Assert.True(comp.Contains(65535));
    }

    [Fact]
    public void Complement_OfAll_IsEmpty()
    {
        Assert.True(PortSet.TryParse("1-65535", out var all, out _));
        var comp = all.Complement();
        Assert.True(comp.IsEmpty);
    }

    [Fact]
    public void Complement_DoubleComplement_EqualsOriginal()
    {
        Assert.True(PortSet.TryParse("80, 443, 8000-8080", out var original, out _));
        var doubleComp = original.Complement().Complement();

        for (int p = 1; p <= 65535; p++)
        {
            Assert.Equal(original.Contains(p), doubleComp.Contains(p));
        }
    }
}
