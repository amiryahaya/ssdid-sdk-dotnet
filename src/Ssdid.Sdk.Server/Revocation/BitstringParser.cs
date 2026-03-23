using System.IO.Compression;
using Ssdid.Sdk.Server.Encoding;

namespace Ssdid.Sdk.Server.Revocation;

/// <summary>
/// Decodes W3C Bitstring Status List encoded lists and checks revocation status.
/// Format: Base64URL → GZIP decompress → bitstring (MSB first per W3C spec).
/// </summary>
public static class BitstringParser
{
    public static bool IsRevoked(string encodedList, int index)
    {
        if (index < 0) throw new ArgumentOutOfRangeException(nameof(index));

        var compressed = SsdidEncoding.Base64UrlDecode(encodedList);
        var bitstring = Decompress(compressed);

        var bytePos = index / 8;
        if (bytePos >= bitstring.Length)
            throw new ArgumentOutOfRangeException(nameof(index), $"Index {index} exceeds bitstring length");

        var bitPos = 7 - (index % 8); // MSB first per W3C spec
        return (bitstring[bytePos] >> bitPos & 1) == 1;
    }

    private static byte[] Decompress(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }
}
