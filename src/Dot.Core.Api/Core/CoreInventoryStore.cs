namespace Dot.Core.Api.Core;

public sealed class CoreInventoryStore
{
    private readonly object syncRoot = new();
    private readonly Dictionary<string, MigrationStatus> migrationStatuses;
    private readonly List<string> decisions = [];

    public CoreInventoryStore()
    {
        Owners = CoreDemoData.CreateOwners();
        Algorithms = CoreDemoData.CreateAlgorithms();
        SeedAssets = CoreDemoData.CreateAssets();
        migrationStatuses = SeedAssets.ToDictionary(asset => asset.Id, asset => asset.MigrationStatus);
        decisions.Add("Seeded demo inventory created for dot Core v26.2.0.");
        decisions.Add("Risk scores are deterministic and derived from stored asset, finding, algorithm, and migration status inputs.");
    }

    public IReadOnlyList<SystemOwner> Owners { get; }
    public IReadOnlyList<AlgorithmProfile> Algorithms { get; }
    private IReadOnlyList<Asset> SeedAssets { get; }

    public IReadOnlyList<Asset> GetAssets()
    {
        lock (syncRoot)
        {
            return SeedAssets.Select(ApplyCurrentStatus).ToArray();
        }
    }

    public Asset? GetAsset(string assetId)
    {
        lock (syncRoot)
        {
            return SeedAssets.Where(asset => asset.Id == assetId).Select(ApplyCurrentStatus).SingleOrDefault();
        }
    }

    public SystemOwner GetOwner(string ownerId)
    {
        return Owners.Single(owner => owner.Id == ownerId);
    }

    public IReadOnlyList<AlgorithmProfile> GetAlgorithmsFor(Asset asset)
    {
        var algorithmIds = asset.Findings.Select(finding => finding.AlgorithmProfileId).Distinct().ToHashSet();

        return Algorithms.Where(algorithm => algorithmIds.Contains(algorithm.Id)).ToArray();
    }

    public IReadOnlyList<string> GetDecisions()
    {
        lock (syncRoot)
        {
            return decisions.ToArray();
        }
    }

    public Asset? UpdateMigrationStatus(string assetId, MigrationStatus status, string? decisionNote)
    {
        lock (syncRoot)
        {
            if (!migrationStatuses.ContainsKey(assetId))
            {
                return null;
            }

            migrationStatuses[assetId] = status;

            var note = string.IsNullOrWhiteSpace(decisionNote)
                ? "No operator note supplied."
                : decisionNote.Trim();
            decisions.Add($"{CoreDemoData.EvidenceGeneratedAt:O}: {assetId} moved to {status}. {note}");

            return SeedAssets.Where(asset => asset.Id == assetId).Select(ApplyCurrentStatus).Single();
        }
    }

    private Asset ApplyCurrentStatus(Asset asset)
    {
        return asset with { MigrationStatus = migrationStatuses[asset.Id] };
    }
}
