using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using System.Globalization;
using Microsoft.Data.SqlClient;
using Dapper; // add package Dapper if you want strong typing, otherwise remove and use raw ExecuteReader

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapPost("/api/claims", GetClaims);

app.Run();

async Task<IResult> GetClaims(HttpRequest req, ILogger log)
{
    // ╔══════════════════════════════════════════════
    // ║               FILL THESE 3 VALUES           ║
    // ╚══════════════════════════════════════════════
    const string SupabaseProjectRef = "abcde12345"; // ← your xxxx in https://xxxx.supabase.co
    const string SqlEndpoint = "your-sql-endpoint.sql.fabric.microsoft.com"; // ← from Fabric Lakehouse → SQL endpoint
    const string LakehouseName = "Claimsify_LH";

    // ╔══════════════════════════════════════════════
    //   JWT validation (Supabase asymmetric JWKS 2025 way)
    // ╚══════════════════════════════════════════════
    if (!req.Headers.Authorization.ToString().StartsWith("Bearer "))
        return Results.Unauthorized();

    var token = req.Headers.Authorization.ToString()["Bearer ".Length..].Trim();

    ClaimsPrincipal? user = await ValidateSupabaseJwt(token, SupabaseProjectRef);
    if (user == null) return Results.Unauthorized();

    string? email = user.FindFirst("email")?.Value;
    if (string.IsNullOrEmpty(email)) return Results.Unauthorized();

    string companyTable = GetCompanyTableName(email);

    // Safety – only alphanumeric table names allowed
    if (!System.Text.RegularExpressions.Regex.IsMatch(companyTable, "^[a-zA-Z0-9]+$"))
        return Results.BadRequest("Invalid company name");

    // ╔══════════════════════════════════════════════
    //   Parse filters from JSON body (Lovable sends JSON)
    // ╚══════════════════════════════════════════════
    var filters = await req.ReadFromJsonAsync<Filters>() ?? new Filters();

    // Build safe parameterized query
    var sql = $"""
        SELECT 
            Claim_ID AS ClaimId,
            policyNumber AS PolicyNumber,
            lossDate AS LossDate,
            status AS Status,
            amountPaid AS AmountPaid,
            lastUpdated AS LastUpdated,
            Claim_ID,
            User_ID,
            Company_Name,
            Entry_Date
            -- add ALL columns you want here (or use SELECT * and cast to dynamic)
        FROM dbo.[{companyTable}]
        WHERE 1= 1
        """ +
        (string.IsNullOrEmpty(filters.InsuredName) ? "" : " AND Insured_Name LIKE @insuredName") +
        (string.IsNullOrEmpty(filters.State) ? "" : " AND State = @state") +
        (string.IsNullOrEmpty(filters.ClaimId) ? "" : " AND Claim_ID LIKE @claimId") +
        (filters.LossDateFrom == null ? "" : " AND lossDate >= @lossDateFrom") +
        (filters.LossDateTo == null ? "" : " AND lossDate <= @lossDateTo") +
        (filters.EntryDateFrom == null ? "" : " AND Entry_Date >= @entryDateFrom") +
        (filters.EntryDateTo == null ? "" : " AND Entry_Date <= @entryDateTo") +
        " ORDER BY Entry_Date DESC"; // or whatever you prefer

    var parameters = new DynamicParameters();
    if (!string.IsNullOrEmpty(filters.InsuredName)) parameters.Add("@insuredName", $"%{filters.InsuredName}%");
    if (!string.IsNullOrEmpty(filters.State)) parameters.Add("@state", filters.State);
    if (!string.IsNullOrEmpty(filters.ClaimId)) parameters.Add("@claimId", $"%{filters.ClaimId}%");
    if (filters.LossDateFrom != null) parameters.Add("@lossDateFrom", filters.LossDateFrom);
    if (filters.LossDateTo != null) parameters.Add("@lossDateTo", filters.LossDateTo);
    if (filters.EntryDateFrom != null) parameters.Add("@entryDateFrom", filters.EntryDateFrom);
    if (filters.EntryDateTo != null) parameters.Add("@entryDateTo", filters.EntryDateTo);

    // ╔══════════════════════════════════════════════
    //   Execute against Fabric using Managed Identity
    // ╚══════════════════════════════════════════════
    var connString = $"Server=tcp:{SqlEndpoint},1433;Initial Catalog={LakehouseName};Encrypt=True;Authentication=Active Directory Managed Identity;";

    await using var conn = new SqlConnection(connString);
    var rows = await conn.QueryAsync(sql, parameters);

    return Results.Ok(new { rows, totalCount = rows.Count() });
}

// ──────────────────────────────────────────────
// Helper classes / methods
// ──────────────────────────────────────────────
record Filters(
    string? InsuredName,
    string? State,
    string? ClaimId,
    DateTime? LossDateFrom,
    DateTime? LossDateTo,
    DateTime? EntryDateFrom,
    DateTime? EntryDateTo);

static string GetCompanyTableName(string email)
{
    var domain = email.Split('@')[1].ToLowerInvariant();
    var part = domain.Split('.')[0];

    // Adjust this to exactly match Lovable's current logic
    // Examples you gave → gmail.com becomes "gmail", beta.com becomes "Beta"
    return part == "gmail" ? "gmail" : CultureInfo.CurrentCulture.TextInfo.ToTitleCase(part);
}

static readonly HttpClient Http = new();
static OpenIdConnectConfiguration? Config = null;

static async Task<ClaimsPrincipal?> ValidateSupabaseJwt(string token, string projectRef)
{
    var authority = $"https://{projectRef}.supabase.co/auth/v1";

    Config ??= await new OpenIdConnectConfigurationRetriever()
        .GetAsync($"{authority}/.well-known/openid-configuration", CancellationToken.None);

    var parameters = new TokenValidationParameters
    {
        ValidIssuer = authority,
        ValidateAudience = false, // Supabase access_token aud = "authenticated"
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = Config.SigningKeys,
        ValidateLifetime = true
    };

    try
    {
        var handler = new JwtSecurityTokenHandler();
        return handler.ValidateToken(token, parameters, out _);
    }
    catch { return null; }
}
