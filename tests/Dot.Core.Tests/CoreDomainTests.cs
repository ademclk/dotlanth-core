using Dot.Core.Api.Core;

namespace Dot.Core.Tests;

public sealed class CoreDomainTests
{
    [Fact]
    public void SeededInventoryContainsRequiredDemoAssets()
    {
        var assets = CoreDemoData.CreateAssets();

        Assert.Equal(5, assets.Count);
        Assert.Contains(assets, asset => asset.Category == AssetCategory.Web);
        Assert.Contains(assets, asset => asset.Category == AssetCategory.Api);
        Assert.Contains(assets, asset => asset.Category == AssetCategory.Database);
        Assert.Contains(assets, asset => asset.Category == AssetCategory.Cicd);
        Assert.Contains(assets, asset => asset.Category == AssetCategory.ThirdPartyDependency);
    }

    [Fact]
    public void SeededInventoryKeepsFindingsAlgorithmsOwnersAndMigrationStatesConnected()
    {
        var owners = CoreDemoData.CreateOwners();
        var algorithms = CoreDemoData.CreateAlgorithms();
        var assets = CoreDemoData.CreateAssets();
        var ownerIds = owners.Select(owner => owner.Id).ToHashSet();
        var algorithmIds = algorithms.Select(algorithm => algorithm.Id).ToHashSet();

        foreach (var asset in assets)
        {
            Assert.False(string.IsNullOrWhiteSpace(asset.Id));
            Assert.False(string.IsNullOrWhiteSpace(asset.Name));
            Assert.Contains(asset.OwnerId, ownerIds);
            Assert.NotEmpty(asset.Findings);
            Assert.True(Enum.IsDefined(asset.MigrationStatus));

            foreach (var finding in asset.Findings)
            {
                Assert.Equal(asset.Id, finding.AssetId);
                Assert.Contains(finding.AlgorithmProfileId, algorithmIds);
                Assert.False(string.IsNullOrWhiteSpace(finding.PlainLanguageReason));
                Assert.False(string.IsNullOrWhiteSpace(finding.RecommendedAction));
            }
        }
    }

    [Fact]
    public void SeededInventoryIncludesHighRiskRsaKeyExchangeAndMigratedControl()
    {
        var assets = CoreDemoData.CreateAssets();

        Assert.Contains(assets, asset =>
            asset.Findings.Any(finding =>
                finding.AlgorithmProfileId == "alg-rsa-2048"
                && finding.Usage.Contains("key exchange", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(assets, asset => asset.MigrationStatus == MigrationStatus.Migrated);
    }
}
