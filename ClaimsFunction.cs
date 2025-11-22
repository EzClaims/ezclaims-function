using Dapper;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.Net;
using System.Security.Claims;

public class ClaimsFunction
{
    private readonly ILogger _logger;

    public ClaimsFunction(ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<ClaimsFunction>();
    }

    [Function("GetClaims")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "claims")] HttpRequestData req)
    {
        try
        {
            _logger.LogInformation("EZclaims retrieval function triggered");

            var supabaseProjectRef = Environment.GetEnvironmentVariable("SupabaseProjectRef");
            var sqlEndpoint = Environment.GetEnvironmentVariable("SqlEndpoint");
            var lakehouseName = Environment.GetEnvironmentVariable("LakehouseName") ?? "Claimsify_LH";

            if (string.IsNullOrEmpty(supabaseProjectRef) || string.IsNullOrEmpty(sqlEndpoint))
            {
                return await JsonError(req, HttpStatusCode.InternalServerError, "Missing app settings (SupabaseProjectRef or SqlEndpoint)");
            }

            // ---------- JWT validation ----------
            if (!req.Headers.TryGetValues("Authorization", out var authHeaders) ||
                !authHeaders.FirstOrDefault()?.StartsWith("Bearer ") ?? true)
            {
                return await JsonError(req, HttpStatusCode.Unauthorized, "Missing Authorization header");
            }

            var token = authHeaders.First()!["Bearer ".Length..].Trim();

            var user = await ValidateSupabaseJwt(token, supabaseProjectRef);
            if (user == null)
            {
                return await JsonError(req, HttpStatusCode.Unauthorized, "Invalid/expired JWT");
            }

            var email = user.FindFirst(ClaimTypes.Email)?.Value ?? user.FindFirst("email")?.Value;
            if (string.IsNullOrEmpty(email))
            {
                return await JsonError(req, HttpStatusCode.Unauthorized, "No email claim in token");
            }

            var companyTable = GetCompanyTableName(email);

            if (!System.Text.RegularExpressions.Regex.IsMatch(companyTable, "^[a-zA-Z0-9_]+$"))
            {
                return await JsonError(req, HttpStatusCode.BadRequest, "Invalid table name derived from email");
            }

            // ---------- Filters ----------
            var filters = await req.ReadFromJsonAsync<Filters>() ?? new Filters();

            var sql = $@"
                SELECT 
                    Claim_ID AS ClaimId,
                    policyNumber AS PolicyNumber,
                    lossDate AS LossDate,
                    status AS Status,
                    amountPaid AS AmountPaid,
                    lastUpdated AS LastUpdated,
                    Insured_Name,
                    State,
                    Claim_ID,
                    User_ID,
                    Company_Name,
                    Entry_Date
                FROM dbo.[{companyTable}]
                WHERE 1=1
                " +
                (string.IsNullOrEmpty(filters.InsuredName) ? "" : " AND Insured_Name LIKE @InsuredName") +
                (string.IsNullOrEmpty(filters.State) ? "" : " AND State = @State") +
                (string.IsNullOrEmpty(filters.ClaimId) ? "" : " AND Claim_ID LIKE @ClaimId") +
                (filters.LossDateFrom == null ? "" : " AND lossDate >= @LossDateFrom") +
                (filters.LossDateTo == null ? "" : " AND lossDate <= @LossDateTo") +
                (filters.EntryDateFrom == null ? "" : " AND Entry_Date >= @EntryDateFrom") +
                (filters.EntryDateTo == null ? "" : " AND Entry_Date <= @EntryDateTo") +
                " ORDER BY Entry_Date DESC";

            var parameters = new DynamicParameters();
            if (!string.IsNullOrEmpty(filters.InsuredName)) parameters.Add("@InsuredName", $"%{filters.InsuredName}%");
            if (!string.IsNullOrEmpty(filters.State)) parameters.Add("@State", filters.State);
            if (!string.IsNullOrEmpty(filters.ClaimId)) parameters.Add("@ClaimId", $"%{filters.ClaimId}%");
            if (filters.LossDateFrom != null) parameters.Add("@LossDateFrom", filters.LossDateFrom);
            if (filters.LossDateTo != null) parameters.Add("@LossDateTo", filters.LossDateTo);
            if (filters.EntryDateFrom != null) parameters.Add("@EntryDateFrom", filters.EntryDateFrom);
            if (filters.EntryDateTo != null) parameters.Add("@EntryDateTo", filters.EntryDateTo);

            var connString = $"Server=tcp:{sqlEndpoint},1433;Database={lakehouseName};Encrypt=True;Authentication=Active Directory Managed Identity;";

            await using var conn = new SqlConnection(connString);
            await conn.OpenAsync();

            var rows = await conn.QueryAsync(sql, parameters);

            var okResponse = req.CreateResponse(HttpStatusCode.OK);
            await okResponse.WriteAsJsonAsync(new { rows = rows.ToList(), totalCount = rows.Count() });
            return okResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled error");
            return await JsonError(req, HttpStatusCode.InternalServerError, ex.Message);
        }
    }

    private async Task<HttpResponseData> JsonError(HttpRequestData req, HttpStatusCode status, string message)
    {
        var resp = req.CreateResponse(status);
        await resp.WriteAsJsonAsync(new { error = message });
        return resp;
    }

    private static string GetCompanyTableName(string email)
    {
        var parts = email.Split('@');
        if (parts.Length != 2) throw new Exception("Invalid email");
        var domain = parts[1].ToLowerInvariant();

        if (domain.EndsWith(".gmail.com") || domain == "gmail.com") return "gmail";

        var companyPart = domain.Split('.')[0];
        return CultureInfo.CurrentCulture.TextInfo.ToTitleCase(companyPart);
    }

    private static readonly HttpClient HttpClient = new();

    private static OpenIdConnectConfiguration? config = null;

    private static async Task<ClaimsPrincipal?> ValidateSupabaseJwt(string token, string projectRef)
    {
        var authority = $"https://{projectRef}.supabase.co/auth/v1";

        config ??= await new OpenIdConnectConfigurationRetriever()
            .GetAsync($"{authority}/.well-known/openid-configuration", CancellationToken.None);

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = authority,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            ValidateLifetime = true
        };

        try
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }
}

public record Filters(
    string? InsuredName = null,
    string? State = null,
    string? ClaimId = null,
    DateTime? LossDateFrom = null,
    DateTime? LossDateTo = null,
    DateTime? EntryDateFrom = null,
    DateTime? EntryDateTo = null);
