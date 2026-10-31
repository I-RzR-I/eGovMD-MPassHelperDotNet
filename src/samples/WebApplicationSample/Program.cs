using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MPassHelperDotNet.XDependencyInjection;
using WebApplicationSample.Authentication;
using WebApplicationSample.Endpoints;
using WebApplicationSample.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddProblemDetails();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSingleton<SamlRequestStateStore>();
builder.Services.AddSingleton<SamlSessionRegistry>();
builder.Services.AddSingleton<SessionRegistryCookieEvents>();

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__Host-MPass.Antiforgery";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "__Host-MPass.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = SamlSessionRegistry.SessionLifetime;
        options.SlidingExpiration = false;
        options.LoginPath = "/account/login";
        options.EventsType = typeof(SessionRegistryCookieEvents);
    });
builder.Services.AddAuthorization();

builder.Services.AddMPassService(builder.Configuration);
builder.Services.AddHealthChecks().AddMPassCertificateHealthCheck();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");
app.MapStatusEndpoints();

app.Run();
