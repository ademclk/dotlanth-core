namespace Dot.Core.Api.Core;

public sealed class CoreRiskScoringService
{
    public FindingRiskScore ScoreFinding(
        Asset asset,
        CryptographicFinding finding,
        AlgorithmProfile algorithm)
    {
        ArgumentNullException.ThrowIfNull(asset);
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(algorithm);

        if (finding.AssetId != asset.Id)
        {
            throw new ArgumentException("Finding does not belong to the supplied asset.", nameof(finding));
        }

        var score = 10;
        var isActiveVulnerability = !finding.IsResolved && algorithm.IsQuantumVulnerable;
        var inputs = new List<string>
        {
            $"finding.id={finding.Id}",
            $"asset.category={asset.Category}",
            $"asset.criticality={asset.Criticality}",
            $"asset.migrationStatus={asset.MigrationStatus}",
            $"finding.resolved={finding.IsResolved}",
            $"algorithm.id={algorithm.Id}",
            $"algorithm.quantumVulnerable={algorithm.IsQuantumVulnerable}",
            $"evidence.source={finding.EvidenceSource}"
        };

        if (asset.Criticality.Equals("Critical", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
        }
        else if (asset.Criticality.Equals("High", StringComparison.OrdinalIgnoreCase))
        {
            score += 14;
        }
        else if (asset.Criticality.Equals("Medium", StringComparison.OrdinalIgnoreCase))
        {
            score += 8;
        }

        if (isActiveVulnerability)
        {
            score += 30;
        }

        if (!finding.IsResolved && finding.Surface.Contains("Public", StringComparison.OrdinalIgnoreCase))
        {
            score += 18;
            inputs.Add("surface.public=true");
        }

        if (!finding.IsResolved
            && asset.Category == AssetCategory.Api
            && finding.Surface.Contains("gateway", StringComparison.OrdinalIgnoreCase))
        {
            score += 6;
            inputs.Add("surface.apiGateway=true");
        }

        if (!finding.IsResolved && finding.Usage.Contains("key exchange", StringComparison.OrdinalIgnoreCase))
        {
            score += 14;
            inputs.Add("usage.keyExchange=true");
        }

        score += asset.MigrationStatus switch
        {
            MigrationStatus.NotStarted => 10,
            MigrationStatus.Investigating => 7,
            MigrationStatus.Planned => 3,
            MigrationStatus.InProgress => 1,
            MigrationStatus.Migrated => -45,
            MigrationStatus.AcceptedRisk => 6,
            _ => 0
        };

        if (finding.IsResolved)
        {
            score -= 20;
        }

        score = Math.Clamp(score, 0, 100);

        return new FindingRiskScore(
            finding.Id,
            asset.Id,
            score,
            GetSeverity(score),
            GetConfidence(finding.IsResolved ? 0 : 1, asset.MigrationStatus),
            finding.Surface,
            BuildFindingReason(asset, finding, algorithm, score),
            BuildFindingRecommendedAction(asset, finding),
            inputs);
    }

    public RiskScore ScoreAsset(Asset asset, IReadOnlyList<AlgorithmProfile> algorithms)
    {
        ArgumentNullException.ThrowIfNull(asset);
        ArgumentNullException.ThrowIfNull(algorithms);

        var unresolvedFindings = asset.Findings.Where(finding => !finding.IsResolved).ToArray();
        var vulnerableAlgorithms = unresolvedFindings
            .Select(finding => algorithms.Single(algorithm => algorithm.Id == finding.AlgorithmProfileId))
            .Where(algorithm => algorithm.IsQuantumVulnerable)
            .ToArray();

        var score = 10;
        var inputs = new List<string>
        {
            $"asset.category={asset.Category}",
            $"asset.criticality={asset.Criticality}",
            $"asset.migrationStatus={asset.MigrationStatus}",
            $"findings.unresolved={unresolvedFindings.Length}",
            $"algorithms.quantumVulnerable={vulnerableAlgorithms.Length}"
        };

        if (asset.Criticality.Equals("Critical", StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
        }
        else if (asset.Criticality.Equals("High", StringComparison.OrdinalIgnoreCase))
        {
            score += 14;
        }
        else if (asset.Criticality.Equals("Medium", StringComparison.OrdinalIgnoreCase))
        {
            score += 8;
        }

        if (vulnerableAlgorithms.Length > 0)
        {
            score += 30;
        }

        if (unresolvedFindings.Any(finding => finding.Surface.Contains("Public", StringComparison.OrdinalIgnoreCase)))
        {
            score += 18;
            inputs.Add("surface.public=true");
        }

        if (asset.Category == AssetCategory.Api
            && unresolvedFindings.Any(finding => finding.Surface.Contains("gateway", StringComparison.OrdinalIgnoreCase)))
        {
            score += 6;
            inputs.Add("surface.apiGateway=true");
        }

        if (unresolvedFindings.Any(finding => finding.Usage.Contains("key exchange", StringComparison.OrdinalIgnoreCase)))
        {
            score += 14;
            inputs.Add("usage.keyExchange=true");
        }

        score += asset.MigrationStatus switch
        {
            MigrationStatus.NotStarted => 10,
            MigrationStatus.Investigating => 7,
            MigrationStatus.Planned => 3,
            MigrationStatus.InProgress => 1,
            MigrationStatus.Migrated => -45,
            MigrationStatus.AcceptedRisk => 6,
            _ => 0
        };

        score = Math.Clamp(score, 0, 100);
        var severity = GetSeverity(score);
        var affectedSurface = unresolvedFindings.FirstOrDefault()?.Surface
            ?? asset.Findings.FirstOrDefault()?.Surface
            ?? "No active finding surface";
        var highestFinding = unresolvedFindings.FirstOrDefault() ?? asset.Findings.FirstOrDefault();

        return new RiskScore(
            asset.Id,
            score,
            severity,
            GetConfidence(unresolvedFindings.Length, asset.MigrationStatus),
            affectedSurface,
            BuildReason(asset, vulnerableAlgorithms, highestFinding, score),
            BuildRecommendedAction(asset, highestFinding),
            inputs);
    }

    private static RiskSeverity GetSeverity(int score)
    {
        return score switch
        {
            >= 85 => RiskSeverity.Critical,
            >= 65 => RiskSeverity.High,
            >= 35 => RiskSeverity.Medium,
            _ => RiskSeverity.Low
        };
    }

    private static decimal GetConfidence(int unresolvedFindingCount, MigrationStatus status)
    {
        if (status == MigrationStatus.Migrated)
        {
            return 0.94m;
        }

        return unresolvedFindingCount > 0 ? 0.88m : 0.72m;
    }

    private static string BuildReason(
        Asset asset,
        IReadOnlyList<AlgorithmProfile> vulnerableAlgorithms,
        CryptographicFinding? finding,
        int score)
    {
        if (asset.MigrationStatus == MigrationStatus.Migrated)
        {
            return $"{asset.Name} is scored {score} because its seeded finding is marked migrated and retained as evidence, not as an active queue item.";
        }

        if (vulnerableAlgorithms.Count == 0 || finding is null)
        {
            return $"{asset.Name} is scored {score} because no unresolved quantum-vulnerable cryptography is attached to the seeded record.";
        }

        var algorithmNames = string.Join(", ", vulnerableAlgorithms.Select(algorithm => algorithm.Name).Distinct());
        return $"{asset.Name} is scored {score} because {algorithmNames} appears on {finding.Surface.ToLowerInvariant()} while the asset is {asset.Criticality.ToLowerInvariant()} and {asset.MigrationStatus}.";
    }

    private static string BuildRecommendedAction(Asset asset, CryptographicFinding? finding)
    {
        if (asset.MigrationStatus == MigrationStatus.Migrated)
        {
            return "Keep the migrated control in the evidence report and revalidate it during the next release window.";
        }

        return finding?.RecommendedAction
            ?? "Keep the asset in inventory and refresh cryptographic evidence before the next readiness review.";
    }

    private static string BuildFindingReason(
        Asset asset,
        CryptographicFinding finding,
        AlgorithmProfile algorithm,
        int score)
    {
        if (asset.MigrationStatus == MigrationStatus.Migrated || finding.IsResolved)
        {
            return $"{finding.Surface} is scored {score} because the seeded finding is resolved or migrated and retained as evidence.";
        }

        if (!algorithm.IsQuantumVulnerable)
        {
            return $"{finding.Surface} is scored {score} because {algorithm.Name} is not marked quantum-vulnerable in the seeded profile.";
        }

        return $"{finding.Surface} is scored {score} because {algorithm.Name} is used for {finding.Usage.ToLowerInvariant()} on a {asset.Criticality.ToLowerInvariant()} asset in {asset.MigrationStatus}.";
    }

    private static string BuildFindingRecommendedAction(Asset asset, CryptographicFinding finding)
    {
        if (asset.MigrationStatus == MigrationStatus.Migrated || finding.IsResolved)
        {
            return "Keep this migrated control attached to the evidence report and revalidate it during the next release window.";
        }

        return finding.RecommendedAction;
    }
}
