# Ssdid.Sdk.Server

.NET server SDK for SSDID (Self-Sovereign Digital Identity) — add DID-based authentication with post-quantum cryptography to any .NET app.

## Packages

| Package | Purpose | Algorithms |
|---------|---------|------------|
| `Ssdid.Sdk.Server` | Core: auth, identity, registry, sessions | Ed25519, ECDSA (P256, P384) |
| `Ssdid.Sdk.Server.PqcNist` | Optional: NIST PQC algorithms | ML-DSA-44/65/87, SLH-DSA (12 variants) |
| `Ssdid.Sdk.Server.KazSign` | Optional: KAZ-Sign PQC algorithm | KAZ-Sign 128/192/256-bit |

## Quick Start

```csharp
// Program.cs
builder.Services.AddSsdidServer(options => {
    options.RegistryUrl = "https://registry.ssdid.my";
    options.IdentityPath = "data/server-identity.json";
    options.Algorithm = "Ed25519VerificationKey2020";
});

// Optional: add post-quantum algorithms
builder.Services.AddSsdidPqcNist();   // ML-DSA + SLH-DSA
builder.Services.AddSsdidKazSign();   // KAZ-Sign
```

## Usage

```csharp
// Inject SsdidAuthService into your endpoints
app.MapPost("/api/auth/register", async (RegisterRequest req, SsdidAuthService auth) => {
    var result = await auth.HandleRegister(req.Did, req.KeyId);
    return result.Match(
        ok => Results.Ok(ok),
        err => Results.Problem(err.Message, statusCode: err.HttpStatus));
});
```

## Supported Algorithms (19 total)

- **Ed25519** — EdDSA (default)
- **ECDSA** — P-256, P-384
- **ML-DSA** — FIPS 204 (44, 65, 87) — *requires PqcNist package*
- **SLH-DSA** — FIPS 205 (SHA2/SHAKE, 128s/128f/192s/192f/256s/256f) — *requires PqcNist package*
- **KAZ-Sign** — Custom PQC (128, 192, 256-bit) — *requires KazSign package + native library*

## License

MIT
