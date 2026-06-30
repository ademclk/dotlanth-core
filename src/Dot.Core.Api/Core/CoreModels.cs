namespace Dot.Core.Api.Core;

public enum AssetCategory
{
    Web,
    Api,
    Database,
    Cicd,
    ThirdPartyDependency
}

public enum MigrationStatus
{
    NotStarted,
    Investigating,
    Planned,
    InProgress,
    Migrated,
    AcceptedRisk
}

public enum RiskSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public sealed record SystemOwner(
    string Id,
    string DisplayName,
    string Team,
    string Email);

public sealed record AlgorithmProfile(
    string Id,
    string Name,
    string Family,
    int? KeySizeBits,
    bool IsQuantumVulnerable,
    string PlainLanguageRisk);

public sealed record CryptographicFinding(
    string Id,
    string AssetId,
    string AlgorithmProfileId,
    string Surface,
    string Usage,
    bool IsResolved,
    string PlainLanguageReason,
    string RecommendedAction,
    string EvidenceSource);

public sealed record Asset(
    string Id,
    string Name,
    AssetCategory Category,
    string Environment,
    string Criticality,
    string OwnerId,
    MigrationStatus MigrationStatus,
    IReadOnlyList<CryptographicFinding> Findings);

public sealed record RiskScore(
    string AssetId,
    int Score,
    RiskSeverity Severity,
    decimal Confidence,
    string AffectedSurface,
    string Reason,
    string RecommendedAction,
    IReadOnlyList<string> Inputs);

public sealed record AssetRiskSummary(
    Asset Asset,
    SystemOwner Owner,
    IReadOnlyList<AlgorithmProfile> Algorithms,
    RiskScore RiskScore);

public sealed record ReadinessSummary(
    string Version,
    DateTimeOffset SeededAt,
    int AssetCount,
    int FindingCount,
    int QuantumVulnerableFindingCount,
    int MigratedControlCount,
    int MigrationQueueCount,
    RiskScore HighestRisk,
    IReadOnlyDictionary<RiskSeverity, int> SeverityCounts);

public sealed record EvidenceAsset(
    string AssetId,
    string AssetName,
    string Owner,
    MigrationStatus MigrationStatus,
    RiskScore RiskScore,
    IReadOnlyList<CryptographicFinding> Findings);

public sealed record EvidenceReport(
    string ReportId,
    string Version,
    DateTimeOffset GeneratedAt,
    ReadinessSummary Summary,
    IReadOnlyList<EvidenceAsset> Assets,
    IReadOnlyList<string> Decisions,
    IReadOnlyList<string> KnownLimitations);

public sealed record MigrationStatusUpdateRequest(
    string Status,
    string? DecisionNote);
