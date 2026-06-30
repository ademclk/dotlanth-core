using Dot.Core.Api;
using Dot.Core.Api.Core;

namespace Dot.Core.Tests;

public sealed class CoreReadinessServiceTests
{
    [Fact]
    public void ReadinessSummaryIsDeterministicAndCountsSeededInventory()
    {
        var service = CreateService();

        var first = service.GetSummary();
        var second = service.GetSummary();

        Assert.Equal(first.Version, second.Version);
        Assert.Equal(first.SeededAt, second.SeededAt);
        Assert.Equal(first.AssetCount, second.AssetCount);
        Assert.Equal(first.FindingCount, second.FindingCount);
        Assert.Equal(first.HighestRisk.Score, second.HighestRisk.Score);
        Assert.Equal(first.HighestRisk.Reason, second.HighestRisk.Reason);
        Assert.Equal(first.SeverityCounts, second.SeverityCounts);
        Assert.Equal(ProductMetadata.Version, first.Version);
        Assert.Equal(5, first.AssetCount);
        Assert.Equal(5, first.FindingCount);
        Assert.Equal(1, first.MigratedControlCount);
        Assert.Equal("asset-payments-api", first.HighestRisk.AssetId);
    }

    [Fact]
    public void MigrationStatusCanMoveThroughCriticalDemoTransition()
    {
        var service = CreateService();

        var updated = service.UpdateMigrationStatus(
            "asset-web-portal",
            MigrationStatus.InProgress,
            "Pilot window approved by platform security.");

        Assert.NotNull(updated);
        Assert.Equal(MigrationStatus.InProgress, updated.Asset.MigrationStatus);
        Assert.Contains("Pilot window approved", service.CreateEvidenceReport().Decisions.Last());
    }

    [Fact]
    public void SeededAssetsReturnStableIdsScoresAndReasonsAcrossRepeatedReads()
    {
        var service = CreateService();

        var first = service.GetAssets();
        var second = service.GetAssets();

        Assert.Equal(
            first.Select(asset => asset.Asset.Id),
            second.Select(asset => asset.Asset.Id));
        Assert.Equal(
            first.Select(asset => asset.RiskScore.Score),
            second.Select(asset => asset.RiskScore.Score));
        Assert.Equal(
            first.Select(asset => asset.RiskScore.Reason),
            second.Select(asset => asset.RiskScore.Reason));
        Assert.Equal(
            first.SelectMany(asset => asset.FindingRiskScores).Select(score => score.Reason),
            second.SelectMany(asset => asset.FindingRiskScores).Select(score => score.Reason));
    }

    [Fact]
    public void AssetSummariesIncludeFindingLevelRiskExplanations()
    {
        var service = CreateService();

        var summaries = service.GetAssets();

        Assert.All(summaries, summary =>
        {
            Assert.Equal(summary.Asset.Findings.Count, summary.FindingRiskScores.Count);
            Assert.All(summary.FindingRiskScores, findingScore =>
            {
                Assert.True(findingScore.Score is >= 0 and <= 100);
                Assert.True(findingScore.Confidence > 0);
                Assert.False(string.IsNullOrWhiteSpace(findingScore.AffectedSurface));
                Assert.False(string.IsNullOrWhiteSpace(findingScore.Reason));
                Assert.False(string.IsNullOrWhiteSpace(findingScore.RecommendedAction));
                Assert.NotEmpty(findingScore.Inputs);
            });
        });
    }

    [Fact]
    public void UnknownAssetMigrationUpdateReturnsNullAndLeavesQueueStable()
    {
        var service = CreateService();
        var before = service.GetMigrationQueue().Select(item => item.AssetId).ToArray();

        var updated = service.UpdateMigrationStatus(
            "asset-not-seeded",
            MigrationStatus.Planned,
            "Should not be stored.");

        Assert.Null(updated);
        Assert.Equal(before, service.GetMigrationQueue().Select(item => item.AssetId));
        Assert.DoesNotContain("Should not be stored", service.CreateEvidenceReport().Decisions);
    }

    [Fact]
    public void EvidenceReportContainsScoresFindingsDecisionsTimestampsAndLimitations()
    {
        var service = CreateService();

        var report = service.CreateEvidenceReport();

        Assert.Equal("dot-core-v26.2.0-readiness-report", report.ReportId);
        Assert.Equal(CoreDemoData.EvidenceGeneratedAt, report.GeneratedAt);
        Assert.NotEmpty(report.Assets);
        Assert.All(report.Assets, asset =>
        {
            Assert.NotNull(asset.RiskScore);
            Assert.NotEmpty(asset.FindingRiskScores);
            Assert.NotEmpty(asset.Findings);
        });
        Assert.NotEmpty(report.Decisions);
        Assert.NotEmpty(report.KnownLimitations);
    }

    [Fact]
    public void MigrationQueueListsUnmigratedAssetsByRisk()
    {
        var service = CreateService();

        var queue = service.GetMigrationQueue();

        Assert.Equal(4, queue.Count);
        Assert.Equal("asset-payments-api", queue[0].AssetId);
        Assert.DoesNotContain(queue, item => item.MigrationStatus == MigrationStatus.Migrated);
        Assert.All(queue, item => Assert.False(string.IsNullOrWhiteSpace(item.RecommendedAction)));
    }

    private static CoreReadinessService CreateService()
    {
        return new CoreReadinessService(new CoreInventoryStore(), new CoreRiskScoringService());
    }
}
