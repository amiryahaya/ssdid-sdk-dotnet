using Ssdid.Sdk.Server;

namespace Ssdid.Sdk.Server.Tests;

public class SsdidDidTests
{
    // A valid suffix: 22 base64url chars representing 128 bits of entropy
    private const string ValidSuffix = "AAAAAAAAAAAAAAAAAAAAAA"; // 22 chars, all base64url

    [Fact]
    public void IsValid_ValidDid_ReturnsTrue()
    {
        var did = $"did:ssdid:{ValidSuffix}";
        Assert.True(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsValid_NullOrEmpty_ReturnsFalse(string? did)
    {
        Assert.False(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData("did:web:example.com")]
    [InlineData("did:key:z6Mk")]
    [InlineData("ssdid:AAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("DID:SSDID:AAAAAAAAAAAAAAAAAAAAAA")]
    public void IsValid_WrongPrefix_ReturnsFalse(string did)
    {
        Assert.False(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData("did:ssdid:short")]           // 5 chars — too short
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAA")] // 21 chars — one below minimum
    public void IsValid_TooShort_ReturnsFalse(string did)
    {
        Assert.False(SsdidDid.IsValid(did));
    }

    [Fact]
    public void IsValid_TooLong_ReturnsFalse()
    {
        // 129 chars — one above maximum
        var did = "did:ssdid:" + new string('A', 129);
        Assert.False(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAA\u00e9")] // accented e
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAA\u4e2d")]  // CJK character
    public void IsValid_UnicodeChars_ReturnsFalse(string did)
    {
        Assert.False(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA+")]  // plus sign
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA/")]  // slash
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA=")]  // equals / padding
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA.")]  // dot
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA ")]  // space
    public void IsValid_SpecialChars_ReturnsFalse(string did)
    {
        Assert.False(SsdidDid.IsValid(did));
    }

    [Theory]
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA")]    // 22 chars, uppercase letters
    [InlineData("did:ssdid:aaaaaaaaaaaaaaaaaaaaaa")]    // 22 chars, lowercase letters
    [InlineData("did:ssdid:0123456789012345678901")]    // 22 chars, digits
    [InlineData("did:ssdid:AAAAAAAAAAAAAAAAAAAAAA-_")]  // 24 chars with hyphen and underscore
    public void IsValid_HyphenUnderscore_ReturnsTrue(string did)
    {
        Assert.True(SsdidDid.IsValid(did));
    }

    [Fact]
    public void Validate_InvalidDid_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SsdidDid.Validate("not-a-did"));
    }

    [Fact]
    public void Validate_NullDid_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => SsdidDid.Validate(null));
    }

    [Fact]
    public void Validate_ValidDid_ReturnsDid()
    {
        var did = $"did:ssdid:{ValidSuffix}";
        var result = SsdidDid.Validate(did);
        Assert.Equal(did, result);
    }
}
