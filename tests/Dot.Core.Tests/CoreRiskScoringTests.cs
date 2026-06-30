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
        var asset = store.GetAsset("asset-web-portal")!;
        var score = scorer.ScoreAsset(asset, store.GetAlgorithmsFor(asset));

        Assert.Equal(RiskSeverity.Critical, score.Severity);
        Assert.True(score.Score >= 85);
        Assert.Contains("RSA-2048", score.Reason);
        Assert.Contains("usage.keyExchange=true", score.Inputs);
        Assert.Contains("hybrid post-quantum TLS pilot", score.RecommendedAction);
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
}
