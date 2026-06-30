using Dot.Core.Api.Core;

namespace Dot.Core.Tests;

public sealed class CoreRiskScoringTests
{
    [Fact]
    public void RiskScoringIsDeterministicForSeededInputs()
    {
        var store = new CoreInventoryStore();
        var scorer = new CoreRiskScoringService();
        var asset = store.GetAsset("asset-web-portal")!;
        var algorithms = store.GetAlgorithmsFor(asset);

        var first = scorer.ScoreAsset(asset, algorithms);
        var second = scorer.ScoreAsset(asset, algorithms);

        Assert.Equal(first.AssetId, second.AssetId);
        Assert.Equal(first.Score, second.Score);
        Assert.Equal(first.Severity, second.Severity);
        Assert.Equal(first.Confidence, second.Confidence);
        Assert.Equal(first.Reason, second.Reason);
        Assert.Equal(first.RecommendedAction, second.RecommendedAction);
        Assert.Equal(first.Inputs, second.Inputs);
    }

    [Fact]
    public void HighRiskRsaKeyExchangeProducesCriticalExplainableScore()
    {
        var store = new CoreInventoryStore();
        var scorer = new CoreRiskScoringService();
        var asset = store.GetAsset("asset-payments-api")!;
        var score = scorer.ScoreAsset(asset, store.GetAlgorithmsFor(asset));

        Assert.Equal(RiskSeverity.Critical, score.Severity);
        Assert.True(score.Score >= 85);
        Assert.Contains("ECDSA P-256", score.Reason);
        Assert.Contains("surface.public=true", score.Inputs);
        Assert.Contains("migration queue", score.RecommendedAction);
    }

    [Fact]
    public void MigratedControlStaysLowRiskAndEvidenceReady()
    {
        var store = new CoreInventoryStore();
        var scorer = new CoreRiskScoringService();
        var asset = store.GetAsset("asset-customer-db")!;
        var score = scorer.ScoreAsset(asset, store.GetAlgorithmsFor(asset));

        Assert.Equal(MigrationStatus.Migrated, asset.MigrationStatus);
        Assert.Equal(RiskSeverity.Low, score.Severity);
        Assert.Contains("migrated", score.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("evidence", score.RecommendedAction, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PlanningGatewayMigrationLowersRiskButKeepsReasonExplainable()
    {
        var store = new CoreInventoryStore();
        var scorer = new CoreRiskScoringService();
        var investigating = store.GetAsset("asset-payments-api")!;
        var planned = investigating with { MigrationStatus = MigrationStatus.Planned };

        var investigatingScore = scorer.ScoreAsset(investigating, store.GetAlgorithmsFor(investigating));
        var plannedScore = scorer.ScoreAsset(planned, store.GetAlgorithmsFor(planned));

        Assert.True(plannedScore.Score < investigatingScore.Score);
        Assert.Equal(RiskSeverity.Critical, plannedScore.Severity);
        Assert.Contains("Planned", plannedScore.Reason);
        Assert.Contains("asset.migrationStatus=Planned", plannedScore.Inputs);
        Assert.Contains("surface.apiGateway=true", plannedScore.Inputs);
    }

    [Fact]
    public void FindingRiskScoringIsDeterministicAndExplainable()
    {
        var store = new CoreInventoryStore();
        var scorer = new CoreRiskScoringService();
        var asset = store.GetAsset("asset-payments-api")!;
        var finding = asset.Findings.Single();
        var algorithm = store.GetAlgorithmsFor(asset).Single();

        var first = scorer.ScoreFinding(asset, finding, algorithm);
        var second = scorer.ScoreFinding(asset, finding, algorithm);

        Assert.Equal(first.FindingId, second.FindingId);
        Assert.Equal(first.AssetId, second.AssetId);
        Assert.Equal(first.Score, second.Score);
        Assert.Equal(first.Severity, second.Severity);
        Assert.Equal(first.Confidence, second.Confidence);
        Assert.Equal(first.AffectedSurface, second.AffectedSurface);
        Assert.Equal(first.Reason, second.Reason);
        Assert.Equal(first.RecommendedAction, second.RecommendedAction);
        Assert.Equal(first.Inputs, second.Inputs);
        Assert.Equal(RiskSeverity.Critical, first.Severity);
        Assert.Contains("finding.id=finding-api-ecdsa-token", first.Inputs);
        Assert.Contains("evidence.source=Seeded dependency manifest", first.Inputs);
        Assert.Contains("Public partner API gateway", first.AffectedSurface);
    }
}
