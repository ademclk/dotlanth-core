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
        Assert.Equal("asset-web-portal", first.HighestRisk.AssetId);
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
    public void EvidenceReportContainsScoresFindingsDecisionsTimestampsAndLimitations()
    {
        var service = CreateService();

        var report = service.CreateEvidenceReport();

        Assert.Equal("dot-core-v26.1.0-readiness-report", report.ReportId);
        Assert.Equal(CoreDemoData.EvidenceGeneratedAt, report.GeneratedAt);
        Assert.NotEmpty(report.Assets);
        Assert.All(report.Assets, asset =>
        {
            Assert.NotNull(asset.RiskScore);
            Assert.NotEmpty(asset.Findings);
        });
        Assert.NotEmpty(report.Decisions);
        Assert.NotEmpty(report.KnownLimitations);
    }

    private static CoreReadinessService CreateService()
    {
        return new CoreReadinessService(new CoreInventoryStore(), new CoreRiskScoringService());
    }
}
