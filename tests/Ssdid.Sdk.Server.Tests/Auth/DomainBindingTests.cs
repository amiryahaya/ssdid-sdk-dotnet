using Ssdid.Sdk.Server.Session;
using Ssdid.Sdk.Server.Session.InMemory;

namespace Ssdid.Sdk.Server.Tests.Auth;

public class DomainBindingTests
{
    [Fact]
    public void Challenge_stores_and_returns_domain()
    {
        var store = new InMemorySessionStore();
        store.CreateChallenge("did:ssdid:test", "registration", "ch123", "key-1", "drive.ssdid.my");

        var entry = store.ConsumeChallenge("did:ssdid:test", "registration");

        Assert.NotNull(entry);
        Assert.Equal("drive.ssdid.my", entry.Domain);
    }

    [Fact]
    public void Challenge_without_domain_returns_null_domain()
    {
        var store = new InMemorySessionStore();
        store.CreateChallenge("did:ssdid:test", "registration", "ch123", "key-1");

        var entry = store.ConsumeChallenge("did:ssdid:test", "registration");

        Assert.NotNull(entry);
        Assert.Null(entry.Domain);
    }
}
