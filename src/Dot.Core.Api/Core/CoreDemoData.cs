namespace Dot.Core.Api.Core;

public static class CoreDemoData
{
    public static readonly DateTimeOffset SeededAt = new(2026, 06, 30, 9, 0, 0, TimeSpan.Zero);
    public static readonly DateTimeOffset EvidenceGeneratedAt = new(2026, 06, 30, 9, 15, 0, TimeSpan.Zero);

    public static IReadOnlyList<SystemOwner> CreateOwners() =>
    [
        new("owner-platform", "A", "Platform Security", "A@example.test"),
        new("owner-payments", "B", "Payments Engineering", "B@example.test"),
        new("owner-data", "C", "Data Platform", "C@example.test"),
        new("owner-devex", "D", "Developer Experience", "D@example.test"),
        new("owner-procurement", "F", "Vendor Risk", "F@example.test")
    ];

    public static IReadOnlyList<AlgorithmProfile> CreateAlgorithms() =>
    [
        new(
            "alg-rsa-2048",
            "RSA-2048",
            "RSA",
            2048,
            true,
            "RSA key exchange is vulnerable to a cryptographically relevant quantum computer and should be replaced with a post-quantum-safe handshake."),
        new(
            "alg-ecdsa-p256",
            "ECDSA P-256",
            "Elliptic curve signature",
            256,
            true,
            "Elliptic curve signatures are quantum-vulnerable and need an approved hybrid or post-quantum replacement path."),
        new(
            "alg-aes-256-gcm",
            "AES-256-GCM",
            "Symmetric encryption",
            256,
            false,
            "AES-256 is not the priority quantum migration concern in this demo when keys are managed correctly."),
        new(
            "alg-sha-256",
            "SHA-256",
            "Hash",
            256,
            false,
            "SHA-256 is retained for this demo inventory and does not create a migration queue item by itself."),
        new(
            "alg-kyber-hybrid",
            "X25519+Kyber768 hybrid",
            "Hybrid key agreement",
            null,
            false,
            "Hybrid key agreement is already migrated for this demo control and is tracked as evidence.")
    ];

    public static IReadOnlyList<Asset> CreateAssets()
    {
        var findings = CreateFindings();

        return
        [
            new(
                "asset-web-portal",
                "Customer Portal TLS Edge",
                AssetCategory.Web,
                "Production",
                "High",
                "owner-platform",
                MigrationStatus.Planned,
                GetFindings("asset-web-portal", findings)),
            new(
                "asset-payments-api",
                "Payments API Gateway",
                AssetCategory.Api,
                "Production",
                "Critical",
                "owner-payments",
                MigrationStatus.Investigating,
                GetFindings("asset-payments-api", findings)),
            new(
                "asset-customer-db",
                "Customer Records Database",
                AssetCategory.Database,
                "Production",
                "Critical",
                "owner-data",
                MigrationStatus.Migrated,
                GetFindings("asset-customer-db", findings)),
            new(
                "asset-ci-runner",
                "Release Signing Pipeline",
                AssetCategory.Cicd,
                "Build",
                "High",
                "owner-devex",
                MigrationStatus.InProgress,
                GetFindings("asset-ci-runner", findings)),
            new(
                "asset-vendor-sdk",
                "Legacy Vendor Payment SDK",
                AssetCategory.ThirdPartyDependency,
                "Production dependency",
                "Medium",
                "owner-procurement",
                MigrationStatus.NotStarted,
                GetFindings("asset-vendor-sdk", findings))
        ];
    }

    private static IReadOnlyList<CryptographicFinding> CreateFindings() =>
    [
        new(
            "finding-web-rsa-key-exchange",
            "asset-web-portal",
            "alg-rsa-2048",
            "Public TLS edge",
            "RSA key exchange in the customer-facing TLS termination path",
            false,
            "The portal still allows RSA key exchange on a public production edge, so harvested traffic could become readable after a future quantum break.",
            "Disable RSA key exchange, prefer ECDHE now, and schedule a hybrid post-quantum TLS pilot for this edge.",
            "Seeded TLS configuration review"),
        new(
            "finding-api-ecdsa-token",
            "asset-payments-api",
            "alg-ecdsa-p256",
            "Public partner API gateway",
            "ECDSA P-256 signs long-lived partner integration tokens at the gateway",
            false,
            "Partner gateway tokens depend on elliptic curve signatures that are not post-quantum-safe and sit on a public production API path.",
            "Move the gateway into the migration queue, inventory token issuers, and design a hybrid signature rollout with partner communication.",
            "Seeded dependency manifest"),
        new(
            "finding-db-hybrid-control",
            "asset-customer-db",
            "alg-kyber-hybrid",
            "Database connection encryption",
            "Hybrid key agreement enabled for service-to-database connections",
            true,
            "The database service has an already-migrated hybrid key agreement control in place for this demo path.",
            "Keep the control in evidence and revalidate during the next platform upgrade.",
            "Seeded migration evidence"),
        new(
            "finding-ci-ecdsa-release",
            "asset-ci-runner",
            "alg-ecdsa-p256",
            "Release signing",
            "ECDSA release signatures for deployable artifacts",
            false,
            "Release signatures are quantum-vulnerable and affect software supply-chain trust.",
            "Create a dual-signing backlog item and define verification support before deprecating ECDSA-only signatures.",
            "Seeded pipeline scan"),
        new(
            "finding-sdk-rsa-cert",
            "asset-vendor-sdk",
            "alg-rsa-2048",
            "Third-party dependency",
            "Vendor SDK pins RSA certificates in a legacy trust bundle",
            false,
            "The third-party SDK contains a pinned RSA trust path and requires owner follow-up before migration can start.",
            "Open a vendor-risk item and request a post-quantum readiness statement plus certificate rotation plan.",
            "Seeded SBOM review")
    ];

    private static IReadOnlyList<CryptographicFinding> GetFindings(
        string assetId,
        IReadOnlyList<CryptographicFinding> findings)
    {
        return findings.Where(finding => finding.AssetId == assetId).ToArray();
    }
}
