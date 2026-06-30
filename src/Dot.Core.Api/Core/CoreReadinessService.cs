namespace Dot.Core.Api.Core;

public sealed class CoreReadinessService(
    CoreInventoryStore store,
    CoreRiskScoringService riskScoring)
{
    public IReadOnlyList<AssetRiskSummary> GetAssets()
    {
        return store.GetAssets().Select(BuildAssetSummary).ToArray();
    }

    public AssetRiskSummary? GetAsset(string assetId)
    {
        var asset = store.GetAsset(assetId);

        return asset is null ? null : BuildAssetSummary(asset);
    }

    public ReadinessSummary GetSummary()
    {
        var assets = GetAssets();
        var scores = assets.Select(asset => asset.RiskScore).ToArray();
        var severityCounts = Enum.GetValues<RiskSeverity>()
            .ToDictionary(severity => severity, severity => scores.Count(score => score.Severity == severity));

        return new ReadinessSummary(
            ProductMetadata.Version,
            CoreDemoData.SeededAt,
            assets.Count,
            assets.Sum(asset => asset.Asset.Findings.Count),
            assets.Sum(asset => asset.Algorithms.Count(algorithm => algorithm.IsQuantumVulnerable)),
            assets.Count(asset => asset.Asset.MigrationStatus == MigrationStatus.Migrated),
            assets.Count(asset => asset.Asset.MigrationStatus is not MigrationStatus.Migrated),
            scores.OrderByDescending(score => score.Score).ThenBy(score => score.AssetId).First(),
            severityCounts);
    }

    public IReadOnlyList<MigrationQueueItem> GetMigrationQueue()
    {
        return GetAssets()
            .Where(asset => asset.Asset.MigrationStatus is not MigrationStatus.Migrated)
            .OrderByDescending(asset => asset.RiskScore.Score)
            .ThenBy(asset => asset.Asset.Id)
            .Select(asset => new MigrationQueueItem(
                asset.Asset.Id,
                asset.Asset.Name,
                asset.Owner.DisplayName,
                asset.Asset.MigrationStatus,
                asset.RiskScore,
                asset.RiskScore.RecommendedAction))
            .ToArray();
    }

    public AssetRiskSummary? UpdateMigrationStatus(string assetId, MigrationStatus status, string? decisionNote)
    {
        var updated = store.UpdateMigrationStatus(assetId, status, decisionNote);

        return updated is null ? null : BuildAssetSummary(updated);
    }

    public EvidenceReport CreateEvidenceReport()
    {
        var assets = GetAssets()
            .OrderByDescending(asset => asset.RiskScore.Score)
            .ThenBy(asset => asset.Asset.Id)
            .Select(asset => new EvidenceAsset(
                asset.Asset.Id,
                asset.Asset.Name,
                asset.Owner.DisplayName,
                asset.Asset.MigrationStatus,
                asset.RiskScore,
                asset.FindingRiskScores,
                asset.Asset.Findings))
            .ToArray();

        return new EvidenceReport(
            "dot-core-v26.2.0-readiness-report",
            ProductMetadata.Version,
            CoreDemoData.EvidenceGeneratedAt,
            GetSummary(),
            assets,
            store.GetDecisions(),
            [
                "Seeded demo data only; no live scanner or external cryptographic inventory is connected.",
                "Risk scores are deterministic heuristics for the v26.2.0 demo and not a compliance attestation.",
                "Migration recommendations identify next actions but do not automatically remediate dependencies."
            ]);
    }

    private AssetRiskSummary BuildAssetSummary(Asset asset)
    {
        var owner = store.GetOwner(asset.OwnerId);
        var algorithms = store.GetAlgorithmsFor(asset);
        var riskScore = riskScoring.ScoreAsset(asset, algorithms);
        var algorithmsById = algorithms.ToDictionary(algorithm => algorithm.Id);
        var findingRiskScores = asset.Findings
            .Select(finding => riskScoring.ScoreFinding(asset, finding, algorithmsById[finding.AlgorithmProfileId]))
            .ToArray();

        return new AssetRiskSummary(asset, owner, algorithms, riskScore, findingRiskScores);
    }
}
