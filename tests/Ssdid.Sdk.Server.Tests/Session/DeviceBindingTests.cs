using Ssdid.Sdk.Server.Session;
using Ssdid.Sdk.Server.Session.InMemory;

namespace Ssdid.Sdk.Server.Tests.Session;

public class DeviceBindingTests
{
    [Fact]
    public void DeviceFingerprint_same_inputs_produce_same_hash()
    {
        var fp1 = DeviceFingerprint.Compute("Mozilla/5.0", "device-123");
        var fp2 = DeviceFingerprint.Compute("Mozilla/5.0", "device-123");
        Assert.Equal(fp1, fp2);
    }

    [Fact]
    public void DeviceFingerprint_different_inputs_produce_different_hash()
    {
        var fp1 = DeviceFingerprint.Compute("Mozilla/5.0", "device-123");
        var fp2 = DeviceFingerprint.Compute("Mozilla/5.0", "device-456");
        Assert.NotEqual(fp1, fp2);
    }

    [Fact]
    public void DeviceFingerprint_handles_nulls()
    {
        var fp = DeviceFingerprint.Compute(null, null);
        Assert.NotNull(fp);
        Assert.Equal(64, fp.Length); // SHA-256 hex = 64 chars
    }

    [Fact]
    public void Session_stores_and_returns_device_fingerprint()
    {
        var store = new InMemorySessionStore();
        var token = store.CreateSession("did:ssdid:test", "fingerprint-abc");

        Assert.NotNull(token);
        Assert.Equal("fingerprint-abc", store.GetSessionDeviceFingerprint(token!));
    }

    [Fact]
    public void Session_without_fingerprint_returns_null()
    {
        var store = new InMemorySessionStore();
        var token = store.CreateSession("did:ssdid:test");

        Assert.NotNull(token);
        Assert.Null(store.GetSessionDeviceFingerprint(token!));
    }

    [Fact]
    public void GetSessionDeviceFingerprint_returns_null_for_unknown_token()
    {
        var store = new InMemorySessionStore();
        Assert.Null(store.GetSessionDeviceFingerprint("nonexistent-token"));
    }
}
