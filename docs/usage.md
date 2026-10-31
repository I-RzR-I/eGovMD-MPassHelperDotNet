> **Note** One thing first, it's not an official helper. This package connects your application to MPass, the sign-in service run by the [e-governance agency](https://egov.md/). Before you install it, contact the agency and discuss the integration with them. You need what they hand over: the MPass identity provider (IdP) metadata with its issuer (EntityID), the MPass login and logout URLs, and the MPass public certificate.

<br/>

**What the package gives you**

The main entry point is `IAuthMPassService`. It has these methods:
* `GenerateAuthRequestAsync` -> builds a signed login request and returns the auto-post form that sends the browser to MPass.
* `GetUserDataFromAuthResponseAsync` -> checks the login response MPass posts back (`SAMLResponse`) and returns the user details.
* `GenerateLogoutRequestAsync` -> builds a signed logout request when the user signs out of your application.
* `ValidateLogoutResponseAsync` -> checks the logout response MPass posts back after that logout.
* `ProcessExternalLogoutRequestAsync` -> checks a logout request started by MPass (or another connected service) and builds the signed logout response.
* `PingAsync` -> sends a GET to the MPass login URL to see if it answers.

`IMPassBuilderService` is the lower-level builder that `IAuthMPassService` uses internally. Most applications never call it. If you do, watch the names: its DTOs use `LogoutRequestId` and `HtmlAuthDocument`, while the `IAuthMPassService` DTOs use `LogOutRequestId` and `HtmlDocument`.

Every method returns `IResult` or `IResult<T>` from `RzR.ResultMessage.Abstractions`. When you cancel the token, the method throws `OperationCanceledException`. Any other unexpected error is logged and comes back as a failed result with a fixed message, so exception details never end up in the result.

For the protocol details and the registration steps on the MPass side, use the documentation you received from the agency.

<br/>
<hr/>

**Configure the application settings file**

The library reads the `MPassSamlOptions` section of your configuration. The example below lists every option you can set. Replace the placeholders with your own values and the values from the agency.

```json
{
  "MPassSamlOptions": {
    "SamlRequestIssuer": "https://your-app.example",
    "SamlServiceLoginDestination": "https://your-app.example/account/acs",
    "SamlServiceLogoutDestination": "https://your-app.example/account/logout-callback",
    "SamlServiceSingleLogoutDestination": "https://your-app.example/account/slo",
    "ServiceCertificatePath": "/path/to/certs/your-app.pfx",
    "IdentityProviderCertificatePath": "/path/to/certs/mpass-idp.cer",
    "IdentityProviderAdditionalCertificatePaths": [],
    "IdentityProviderIssuer": "<MPass IdP metadata EntityID>",
    "SamlLoginDestination": "https://<mpass-host>/login/saml",
    "SamlLogoutDestination": "https://<mpass-host>/logout/saml",
    "SamlMessageTimeout": "00:10:00",
    "SamlClockSkew": "00:02:00",
    "SamlMessageMaxLength": 262144,
    "AllowSha1Signatures": false
  }
}
```

Keep the PFX and CER files out of source control.

The service certificate password is required too, but it is missing from the file on purpose. Keep it out of `appsettings.json`. In development use user-secrets (the project needs a `UserSecretsId`). On a server use the environment variable `MPassSamlOptions__ServiceCertificatePassword` or your secret store.

```
dotnet user-secrets set "MPassSamlOptions:ServiceCertificatePassword" "<pfx-password>"
```

The `IdentityProviderIssuer` value above is a placeholder, and startup validation rejects it. Put the real EntityID from the MPass IdP metadata there. The same goes for values starting with `__SET_`, like the `__SET_FROM_MPASS_IDP_METADATA_ENTITYID__` used in the samples.

Option reference. "Required" means the value is not empty, has no leading or trailing whitespace and does not start with `__SET_` (any case). "URL rule" means required plus an absolute `http` or `https` URL. A plain `http` URL with a non-loopback host only logs a warning ("SAML messages are sent unencrypted. Use https in production."); it does not stop the host.

| Option | Type | Default | Required | What it is |
|---|---|---|---|---|
| `SamlRequestIssuer` | string | null | yes | Your service identifier, usually its public URL. Sent as the Issuer of your messages and expected as the Audience of MPass assertions. |
| `SamlServiceLoginDestination` | string | null | yes, URL rule | Your URL where MPass posts the login response. Must match the response Destination. |
| `SamlServiceLogoutDestination` | string | null | yes, URL rule | Your URL where MPass posts the logout response. Must match its Destination. |
| `SamlServiceSingleLogoutDestination` | string | null | yes, URL rule | Your URL where MPass posts a logout request it started. Must match its Destination. |
| `ServiceCertificatePath` | string | null | yes | Path to your service certificate (with private key). See **Certificates**. |
| `ServiceCertificatePassword` | string | null | yes | Password of the service certificate. Not checked on its own, but without it the certificate is not loaded and startup fails. Cleared after load. |
| `IdentityProviderCertificatePath` | string | null | yes | Path to the MPass public certificate. |
| `IdentityProviderAdditionalCertificatePaths` | string[] | null | no | Extra MPass certificates for rotation. Every listed path must load. Blank entries are skipped and repeated identical paths are removed. |
| `IdentityProviderIssuer` | string | null | yes | The MPass EntityID from the IdP metadata. Every message and assertion from MPass must carry exactly this issuer. |
| `SamlLoginDestination` | string | null | yes, URL rule | MPass login URL. The login form posts here and `PingAsync` calls it. |
| `SamlLogoutDestination` | string | null | yes, URL rule | MPass logout URL. Logout requests and responses go here. |
| `SamlMessageTimeout` | TimeSpan | 00:10:00 | no | How old an incoming message may be. Above zero and at most 00:30:00. |
| `SamlClockSkew` | TimeSpan | 00:02:00 | no | Tolerance for clock differences between your server and MPass. From 00:00:00 to 00:05:00. |
| `SamlMessageMaxLength` | int | 262144 | no | Maximum length, in characters, of an incoming Base64 SAML message. Above zero. |
| `AllowSha1Signatures` | bool | false | no | Accept RSA-SHA1 signatures and SHA-1 digests from MPass. When false, only RSA-SHA256/384/512 and SHA-256/384/512 are accepted. |

<hr/>

**Startup validation**

`AddMPassService` registers the options with `ValidateOnStart()`. A wrong setting stops the host at startup instead of failing the first time a user tries to sign in. The library collects every problem and throws one `OptionsValidationException` that lists all of them, so you fix the whole configuration in one pass.

What gets checked:
* every required setting is filled, has no surrounding whitespace and is not a `__SET_` placeholder;
* `IdentityProviderIssuer` is not the literal `<MPass IdP metadata EntityID>`;
* the five destination settings are absolute `http` or `https` URLs;
* `SamlMessageTimeout`, `SamlClockSkew` and `SamlMessageMaxLength` are within the ranges in the table;
* the service certificate loads, has a private key and an RSA key of at least 2048 bits;
* there is at least one IdP certificate, and every IdP certificate loads, uses an RSA key of at least 2048 bits and has no private key.

Every message names the setting as `MPassSamlOptions.<Name>`. A few you will likely meet:

```
Value cannot be null. Parameter name: MPassSamlOptions.IdentityProviderIssuer
MPassSamlOptions.SamlLoginDestination must be an absolute http or https URL.
Invalid service certificate path or password! (MPassSamlOptions.ServiceCertificatePath, MPassSamlOptions.ServiceCertificatePassword)
```

<hr/>

**Certificates**

You work with two kinds:
* service certificate -> your own certificate with its private key. The library signs the messages you send to MPass with it.
* IdP certificate -> the MPass public certificate. The library uses it to check the signatures on what MPass sends you.

Formats the IdP certificate can have, tried in this order:
* a PEM file -> the first `BEGIN CERTIFICATE` block is used, any other blocks in the chain are ignored;
* a DER (binary) `.cer` file;
* a directory that contains `tls.crt` (PEM).

Formats for the service certificate:
* a PFX (PKCS#12) file with its password -> in the `netstandard2.1` build, which .NET Core 3.x and .NET 5+ hosts use, the last certificate in the file is used. The `netstandard2.0` build (for example on .NET Framework) reads the file as a single certificate and leaves the choice to .NET, so the "last certificate" rule does not apply there. To get the same result in both builds, use a PFX that holds only your service certificate and its key;
* a directory with `tls.crt` and `tls.key` (both PEM) -> only in the `netstandard2.1` build. The `netstandard2.0` build supports only the PFX file.

The password must be non-empty in both cases, even for the directory form. A PFX without a password is not accepted. `tls.key` must be a PKCS#1 `RSA PRIVATE KEY` file. An `EC PRIVATE KEY` file also loads but fails startup validation, because the key must be RSA. A PKCS#8 `PRIVATE KEY` file is not supported, and neither is DSA.

Paths are used exactly as you write them. The library does not combine them with the content root or the application base directory, so a relative path is resolved against the current working directory of the process. That directory depends on how the process is started. A relative path that works under `dotnet run` in the project folder can point somewhere else once the published app is started by a service host. Use absolute paths, or make sure the files sit where the working directory of the running process points.

Certificates are loaded once, when the options are first built. After loading, `ServiceCertificatePassword` is set to null, so the password does not stay in the options object.

When MPass moves to a new certificate, add its path to `IdentityProviderAdditionalCertificatePaths`. A signature is accepted when it verifies with the primary certificate or with any of the additional ones. Do not list the same certificate twice, even under different paths: duplicates are detected by thumbprint and startup validation reports the path list as invalid.

<hr/>

**Calling the service**

After the configuration is in place, register the service. In `Startup.cs`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddMPassService(Configuration);

    ...
}
```

With minimal hosting in `Program.cs`:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMPassService(builder.Configuration);
```

`AddMPassService` lives in the `MPassHelperDotNet.XDependencyInjection` namespace. It binds the `MPassSamlOptions` section, turns on startup validation and registers `IAuthMPassService` and `IMPassBuilderService` as scoped services. It also adds logging, `TimeProvider.System` and the default replay cache. If you call it twice, nothing is registered twice.

Then inject `IAuthMPassService` into your authentication controller:

```csharp
public class AuthController : ControllerBase
{
    private readonly IAuthMPassService _authMPassService;

    public AuthController(IAuthMPassService authMPassService)
        => _authMPassService = authMPassService;

    ...
}
```

**Replay cache**

Each message from MPass is accepted once. The library remembers the IDs of login responses, assertions, logout requests and logout responses, and rejects a second copy with "Invalid SAML message, the message was already processed!".

The default `InMemorySamlReplayCache` keeps those IDs in process memory, up to 100 000 entries. Expired entries are removed during normal use. If the cache is full and nothing has expired, new messages are rejected until old entries expire.

If you run more than one instance, each one has its own memory and cannot see what the others accepted. Register your own `ISamlReplayCache` backed by a shared store. You can register it before or after `AddMPassService`; both work.

```csharp
public sealed class SharedSamlReplayCache : ISamlReplayCache
{
    public Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
    {
        // Add messageId to your shared store only if it is not there yet (one atomic operation),
        // keep it until expiresAtUtc, and return true only when this call added it.
        throw new NotImplementedException();
    }
}

services.AddSingleton<ISamlReplayCache, SharedSamlReplayCache>();
```

Return `true` when the ID was not seen before (or its entry expired). Return `false` when it was already seen or the store cannot take new entries. The interface is in `MPassHelperDotNet.Abstractions.Services.Replay`.

<hr/>

**Login flow**

A login takes two trips. Your application sends the browser to MPass with a signed request, and MPass sends the browser back with a signed response. You connect the two with the auth request ID, which you keep on your side between the trips.

1. The user clicks "Sign in with MPass". Call `GenerateAuthRequestAsync` with a `GenerateAuthRequestDto`.
2. Store the returned `AuthRequestId` on the server, tied to this browser session.
3. Return the returned `HtmlDocument` as the response, with `Cache-Control: no-store`. The browser submits it to MPass by itself.
4. The user signs in at MPass, and MPass posts the `SAMLResponse` form value to your `SamlServiceLoginDestination`.
5. In that action, take the stored ID out of storage, then call `GetUserDataFromAuthResponseAsync` with the `SAMLResponse` value and that ID.
6. On success, sign the user in with a new authentication cookie. Keep `UserInfo.Idnp` and `SessionIndexId` on the server and put only an opaque key in the cookie. You need both values for logout.

The WebApplicationSample does exactly this: it keeps both values in `IDistributedCache` and the authentication cookie carries only a session ID. `Idnp` and the user attributes are personal data, so keep them out of your logs.

`GenerateAuthRequestDto` fields:
* `RelayState` -> required, at most 80 bytes in UTF-8. Longer values fail with "RelayState is too long, the maximum length is 80 bytes (UTF-8)!".
* `ForceAuthn` -> optional. Asks MPass to authenticate the user again even if there is already an MPass session.
* `IsPassive` -> optional. Asks MPass not to interact with the user. If the user has no MPass session, the response fails with "Passive authentication is not possible, the user is not signed in at MPass!". Send the user through a normal login in that case.
* `Language` -> optional, `ro`, `ru` or `en` (trimmed, any case). Added as `lang=<value>` to `SamlLoginDestination`, unless that URL already has a `lang` parameter. Other values fail with "Language is not supported, the allowed values are: ro, ru, en!".

A short sketch of both actions. `SavePendingRequestIdAsync` and `TakePendingRequestIdAsync` stand for your own server-side storage code:

```csharp
[HttpGet("login")]
public async Task<IActionResult> Login(CancellationToken cancellationToken)
{
    var result = await _authMPassService.GenerateAuthRequestAsync(
        new GenerateAuthRequestDto { RelayState = "login", Language = "ro" },
        cancellationToken);

    if (!result.IsSuccess)
        return BadRequest();

    await SavePendingRequestIdAsync(result.Response.AuthRequestId);

    Response.Headers["Cache-Control"] = "no-store";
    return Content(result.Response.HtmlDocument, "text/html");
}

[HttpPost("acs")]
public async Task<IActionResult> Acs([FromForm(Name = "SAMLResponse")] string samlResponse, CancellationToken cancellationToken)
{
    // Read and remove in one step, before validation, whatever the outcome.
    var authRequestId = await TakePendingRequestIdAsync();

    var result = await _authMPassService.GetUserDataFromAuthResponseAsync(
        new GetUserDataFromAuthResponseDto { SamlResponse = samlResponse, AuthRequestId = authRequestId },
        cancellationToken);

    if (!result.IsSuccess)
        return Unauthorized();

    // Issue a new auth cookie that holds only an opaque key; keep
    // result.Response.UserInfo.Idnp and result.Response.SessionIndexId on the server.
    ...
}
```

**Where to keep the request IDs**

The same rules apply to `AuthRequestId` and to `LogOutRequestId`:
* store the ID per browser session in server-side storage (session, distributed cache). Never put the ID itself in a client value. The WebApplicationSample keeps it in `IDistributedCache` under an opaque cookie key;
* take it (read and remove) before you validate the response, whatever the outcome, so it is used only once;
* never accept it from the POST body or from the `RelayState`.

The library compares the response's InResponseTo with the ID you pass. That comparison only means something when the expected ID comes from your own storage.

**What `GetUserDataFromAuthResponseAsync` checks**

Response checks:
* size within `SamlMessageMaxLength`, valid Base64 and valid XML (DTDs are not allowed);
* the signature verifies with an IdP certificate and uses an allowed algorithm;
* the issue time is within `SamlMessageTimeout` plus `SamlClockSkew`;
* Destination equals `SamlServiceLoginDestination`;
* InResponseTo equals your stored `AuthRequestId`;
* Issuer equals `IdentityProviderIssuer`;
* the status is Success;
* the response ID was not accepted before.

Assertion checks:
* exactly one assertion, not encrypted;
* the issuer is the expected one;
* the time conditions hold, with `SamlClockSkew`;
* the Audience is `SamlRequestIssuer`;
* it contains a SessionIndex, a NameID and a bearer confirmation;
* the assertion ID was not accepted before.

On success you get:
* `UserInfo` -> an `AuthMPassUserInfo` with `Idnp` (the NameID), `NameIdentifier`, `RequestId`, `FirstName`, `LastName`, `PhoneNumber`, `HomePhone`, `MobilePhoneNumber`, `Email`, `Gender`, `BirthDate`, `Language`, `AuthIp`, `IsResident`, `AdministeredLegalEntity`, `Idno` and `CompanyName`;
* `UserAttributes` -> the attributes as `Dictionary<string, IList<string>>`;
* `SessionIndexId` -> the MPass session index. Keep it for logout.

<hr/>

**Logout started by your application**

End the local session before you send the browser to MPass. If MPass never posts back, the user is still signed out of your application. The WebApplicationSample works the same way.

1. Read `UserInfo.Idnp` and `SessionIndexId` from your server-side session, then end the local session and sign the user out.
2. Call `GenerateLogoutRequestAsync` with a `GenerateLogOutRequestDto`:
   * `SessionIndexId` -> saved at login;
   * `RelayState` -> required, at most 80 bytes in UTF-8;
   * `UserIdentifierId` -> the user's IDNP (`UserInfo.Idnp` saved at login).
3. Store the returned `LogOutRequestId` server-side, under the same rules as the auth request ID. It must not go into the session you just ended. Use storage that outlives the sign-out, for example a server-side entry reached through a separate opaque cookie key. The WebApplicationSample does this in `SamlRequestStateStore`.
4. Return `HtmlDocument` with `Cache-Control: no-store`. The browser posts it to MPass.
5. MPass posts the logout response to your `SamlServiceLogoutDestination`. Take the stored `LogOutRequestId` and call `ValidateLogoutResponseAsync` with it and the `SAMLResponse` value.
6. If validation fails, tell the user they are signed out of your application but the MPass logout could not be confirmed.

`ValidateLogoutResponseAsync` runs the same envelope checks as the login response: size, XML, signature, issue time, Destination (here `SamlServiceLogoutDestination`), InResponseTo and Issuer. The status must be `Success` or `PartialLogout`, and each response is accepted once.

**External logout request (started by MPass)**

MPass can start a logout itself, for example when the user signs out in another service connected to MPass. It posts a logout request to your `SamlServiceSingleLogoutDestination`.

1. In that action, call `ProcessExternalLogoutRequestAsync` with a `ProcessExternalLogoutRequestDto`:
   * `SamlRequest` -> the posted `SAMLRequest` value, required;
   * `RelayState` -> optional, at most 80 bytes in UTF-8;
   * `SessionIndexId` -> required; the logout request must contain a SessionIndex equal to it;
   * `UserIdentifierId` -> required; the NameID in the logout request must match it.
2. When the result is successful, end the local session.
3. Return the returned `HtmlDocument` with `Cache-Control: no-store`. It posts a signed logout response to `SamlLogoutDestination`. The result also carries its `LogoutResponseId`.

The library checks the signature, the issue time, the Destination and the Issuer. The request must have exactly one NameID that matches `UserIdentifierId`, and a SessionIndex equal to your `SessionIndexId`. Each logout request is processed only once.

This is why you store `UserInfo.Idnp` and `SessionIndexId` at login: without them you have nothing to pass here.

**When the local session is already gone**

Sometimes a logout response or an MPass logout request arrives after the local session has expired. You then have no stored request ID or session index to pass, and you need to decide what to do. The library does not handle this case for you; the WebApplicationSample handles it explicitly in its `AccountController`.

<hr/>

**Cookies and response headers**

* `Cache-Control: no-store` -> send it with every `HtmlDocument` the library returns. Each one carries a single-use signed SAML message.
* The auto-post form -> a POST form with hidden `SAMLRequest` or `SAMLResponse` and `RelayState` fields, plus a Continue button for browsers without JavaScript. The library HTML-encodes the values it puts into it.
* Cookies -> the library itself says nothing about cookies; this part comes from the samples. MPass posts back to you from another site, so a cookie you need on that POST must be `SameSite=None; Secure`. The WebApplicationSample keeps its pending-request cookie as `SameSite=None; Secure; HttpOnly` and its authentication cookie as `SameSite=Lax`.
* Result messages -> they are plain text and can contain text sent by MPass (for example its status message). HTML-encode them before you show them on a page. The sample uses `HtmlEncoder` for that.

<hr/>

**Health check**

The package has a health check for the configured certificates. Add it in `Startup.cs`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddHealthChecks()
                .AddMPassCertificateHealthCheck("MPass");

    ...
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    ...

    app.UseHealthChecks("/health");

    ...
}
```

`AddMPassCertificateHealthCheck()` without a name registers the check as `"MPass"`. Both overloads also accept a `failureStatus` and `tags`.

It looks at the service certificate and at every IdP certificate, the additional ones included:
* Healthy -> no problem found.
* Degraded -> a certificate expires in less than 30 days.
* Unhealthy (or the `failureStatus` you registered) -> no IdP certificate, no service certificate, a service certificate without a private key, or an expired certificate.

All problems are joined with "; " in the description. IdP certificates are named with their thumbprint, so you can tell which one is about to expire.

**PingAsync**

`PingAsync(CancellationToken cancellationToken)` sends a GET to `SamlLoginDestination` and reads only the headers. The token has no default value, so pass one.

The result is always successful unless you cancel (then it throws `OperationCanceledException`). To see whether MPass answered, read `Response.IsSuccess`:
* `Response.IsSuccess` -> true when MPass returned a 2xx status;
* `Response.Message` -> "Server is available.", "Communication problem. Server respond with code: <StatusCode>" or, when the request throws, just "Communication problem";
* `Response.Time` -> how long the call took.

The ping uses one static `HttpClient` for the whole process. It is not registered in DI, and the library sets no timeout, so the .NET default applies.

Keep `/health` and any endpoint that calls `PingAsync` internal or behind authentication. Each ping makes an outbound call to MPass.

<hr/>

**Troubleshooting**

* "Invalid service certificate path or password!" at startup -> the service certificate did not load. Check that the password is set (user-secrets or environment variable) and correct, and that the path exists for the running process. Relative paths are resolved against the current working directory, so try an absolute path first.
* `OptionsValidationException` at startup -> read the whole message. It lists every invalid setting by name. Placeholders (`__SET_...`, `<MPass IdP metadata EntityID>`) and stray spaces count as missing values.
* "Invalid SAML Response signature!" -> the response was not signed with a certificate you configured. Check `IdentityProviderCertificatePath`; if MPass moved to a new certificate, add it to `IdentityProviderAdditionalCertificatePaths`. If MPass signs with SHA-1, the signature is rejected unless `AllowSha1Signatures` is true.
* "Invalid SAML message, the issuer is missing or not expected!" -> `IdentityProviderIssuer` does not exactly match the EntityID MPass sends. Copy it from the IdP metadata.
* "Invalid SAML Response, current response is not for this Service!" -> the URL MPass posted to differs from `SamlServiceLoginDestination` (login response) or `SamlServiceLogoutDestination` (logout response). The comparison ignores case but nothing else.
* "Invalid SAML Response, current response not expected (Different SAML reference id)! Auth is not for this service!" -> the ID you passed is not the one this response answers. Check that you store the `AuthRequestId` per browser session and pass the stored value.
* "Invalid SAML Response, current response is expired!" -> the message is older than `SamlMessageTimeout` or the server clocks differ. Sync your server clock; if needed, raise `SamlClockSkew` (at most 00:05:00).
* "Invalid SAML message, the message was already processed!" -> the same message arrived a second time, or the in-memory replay cache is full.
* "Authentication canceled!" -> MPass answered with the `AuthnFailed` status, so the user did not complete the sign-in.

<hr/>

### Upgrading from 1.x

Version 2.0 has breaking changes. Method names, DI method names and DTO property names are the same as in 1.x. What changed is what the library expects from you and what it checks. Go through the list below; each item is what changed -> what to do.

* Target frameworks -> the package now targets `netstandard2.0` and `netstandard2.1`. Your application must be able to consume one of them.
* Result types -> `IResult` moved from `AggregatedGenericResultMessage.Abstractions` to `RzR.ResultMessage.Abstractions`. Replace the `AggregatedGenericResultMessage` reference with `RzR.ResultMessage` 4.0.0 and update your `using` lines.
* Other dependencies -> `DomainCommonExtensions` 4.5.0.7408 became `RzR.Extensions.Domain` 7.1.0.5494, `UniqueServiceCollection` 1.0.5.8331 became `RzR.Extensions.UniqueServiceCollection` 3.2.0.662, the `Microsoft.Extensions.*` packages and `System.Security.Cryptography.Xml` moved to 10.0.14, and `Microsoft.Bcl.TimeProvider` was added. Update any direct references you have to the old packages so the versions line up.
* `IdentityProviderIssuer` -> new and required. Set it to the EntityID from the MPass IdP metadata; incoming messages must carry exactly this issuer.
* Startup validation -> the host now refuses to start with one exception listing every problem: empty or placeholder settings, surrounding whitespace, non-http(s) destinations, `SamlMessageTimeout` outside 0 to 00:30:00, `SamlClockSkew` outside 00:00:00 to 00:05:00, `SamlMessageMaxLength` not above zero, keys that are not RSA of at least 2048 bits, a service certificate without a private key, or an IdP certificate with one. Start the app once after upgrading and fix everything it lists.
* New optional settings -> `SamlClockSkew` (00:02:00), `AllowSha1Signatures` (false), `SamlMessageMaxLength` (262144) and `IdentityProviderAdditionalCertificatePaths`. The defaults work for most setups; add them only when you need other values.
* SHA-1 signatures -> rejected by default. Set `AllowSha1Signatures` to true only if MPass still signs with SHA-1 for you.
* Request IDs -> `GetUserDataFromAuthResponseDto.AuthRequestId` and `ValidateLogoutResponseDto.LogOutRequestId` are now required. Store both IDs server-side, take them before validation whatever the outcome, and never read them from the POST body or the `RelayState`.
* `RelayState` -> required on login and logout requests and limited to 80 bytes in UTF-8. Check the values you send.
* External logout request -> `ProcessExternalLogoutRequestDto.SamlRequest`, `SessionIndexId` and `UserIdentifierId` are now required, and the incoming logout request must match the last two. Store `UserInfo.Idnp` and `SessionIndexId` at login.
* New login fields -> `ForceAuthn`, `IsPassive` and `Language` (`ro`, `ru`, `en`) on `GenerateAuthRequestDto`. If you use `IsPassive`, handle the "not signed in at MPass" result by falling back to a normal login.
* HTML documents -> serve every returned `HtmlDocument` with `Cache-Control: no-store`.
* `PingAsync` -> the result is successful even when MPass is unreachable. Check `Response.IsSuccess`. On an exception the message is now just "Communication problem"; 1.x appended the exception text.
* Error messages -> failed results carry fixed messages and the exception goes to the log. If you parsed exception text out of results, read your logs instead.
* Replay cache -> every incoming message is accepted once. The default `InMemorySamlReplayCache` works for a single instance. With several instances, register your own `ISamlReplayCache` backed by a shared store.
* `ServiceCertificatePassword` -> cleared from the options after the certificate loads. Do not read it back from `MPassSamlOptions` in your own code.
