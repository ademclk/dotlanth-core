using Dot.Core.Api;
using Dot.Core.Api.Core;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();
builder.Services.AddOpenApi();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyHeader()
            .AllowAnyMethod()
            .AllowAnyOrigin();
    });
});
builder.Services.AddSingleton<CoreInventoryStore>();
builder.Services.AddSingleton<CoreRiskScoringService>();
builder.Services.AddSingleton<CoreReadinessService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors();
app.MapDefaultEndpoints();
app.MapGet("/", () => Results.Redirect("/status")).ExcludeFromDescription();
app.MapGet("/status", (IConfiguration configuration, IHostEnvironment environment) =>
{
    return Results.Ok(new ProductStatus(
        ProductMetadata.Product,
        ProductMetadata.ServiceName,
        ProductMetadata.Version,
        ProductMetadata.Route,
        environment.EnvironmentName,
        HasConnectionString(configuration, "postgres"),
        HasConnectionString(configuration, "valkey")));
})
.WithName("GetCoreStatus");
app.MapGet("/readiness", (CoreReadinessService readiness) => Results.Ok(readiness.GetSummary()))
    .WithName("GetCoreReadinessSummary");
app.MapGet("/assets", (CoreReadinessService readiness) => Results.Ok(readiness.GetAssets()))
    .WithName("GetCoreAssets");
app.MapGet("/assets/{assetId}", (string assetId, CoreReadinessService readiness) =>
{
    var asset = readiness.GetAsset(assetId);

    return asset is null ? Results.NotFound() : Results.Ok(asset);
})
.WithName("GetCoreAsset");
app.MapGet("/migration-queue", (CoreReadinessService readiness) => Results.Ok(readiness.GetMigrationQueue()))
    .WithName("GetCoreMigrationQueue");
app.MapPatch("/assets/{assetId}/migration-status", (
    string assetId,
    MigrationStatusUpdateRequest request,
    CoreReadinessService readiness) =>
{
    if (!Enum.TryParse<MigrationStatus>(request.Status, ignoreCase: true, out var status))
    {
        return Results.BadRequest(new
        {
            error = "Unsupported migration status.",
            allowed = Enum.GetNames<MigrationStatus>()
        });
    }

    var asset = readiness.UpdateMigrationStatus(assetId, status, request.DecisionNote);

    return asset is null ? Results.NotFound() : Results.Ok(asset);
})
.WithName("UpdateCoreMigrationStatus");
app.MapGet("/evidence-report", (CoreReadinessService readiness) => Results.Ok(readiness.CreateEvidenceReport()))
    .WithName("ExportCoreEvidenceReport");

app.Run();

static bool HasConnectionString(IConfiguration configuration, string name)
{
    return !string.IsNullOrWhiteSpace(configuration.GetConnectionString(name));
}

public sealed record ProductStatus(
    string Product,
    string Service,
    string Version,
    string FrontendRoute,
    string Environment,
    bool HasPostgresConnection,
    bool HasValkeyConnection);
