> **Note** This library targets `netstandard2.0` and `netstandard2.1`. On .NET Framework the `netstandard2.0` build is used; on .NET Core 3.x and .NET 5+ the `netstandard2.1` build.

[![NuGet Version](https://img.shields.io/nuget/v/MPassHelperDotNet.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/MPassHelperDotNet/)
[![Nuget Downloads](https://img.shields.io/nuget/dt/MPassHelperDotNet.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/MPassHelperDotNet)

One important reason for developing this repository is to quickly implement the governmental authentication service provided by the [e-governance agency](https://egov.md/), named `MPass`, available in the Republic of Moldova.<br/>

You can read more about the service on the [<a href="https://mpass.gov.md"><img src="assets/mpass.png" width="100px"/></a>](https://mpass.gov.md).

This repository came out of several projects where I implemented MPass from scratch every time. That took a lot of time, and I wanted an easier way to add it to new projects. The library is a wrapper around MPass, the identity provider (IdP): you fill in a few settings in `appsettings.json`, inject one service, and call it from your controllers.

<hr/>

## Install

**In case you wish to use it in your project, you can install the package from <a href="https://www.nuget.org/packages/MPassHelperDotNet" target="_blank">nuget.org</a>** or specify what version you want:

> `Install-Package MPassHelperDotNet -Version x.x.x.x`

With the .NET CLI:

> `dotnet add package MPassHelperDotNet`

<hr/>

## Minimal configuration

**Configure the application settings file**

Add an `MPassSamlOptions` section to `appsettings.json`. These are the settings you must fill in. Replace the values in angle brackets and the `your-app.example` host with your own.

```json
{
  "MPassSamlOptions": {
    "SamlRequestIssuer": "https://your-app.example",
    "SamlServiceLoginDestination": "https://your-app.example/account/acs",
    "SamlServiceLogoutDestination": "https://your-app.example/account/logout-callback",
    "SamlServiceSingleLogoutDestination": "https://your-app.example/account/slo",
    "ServiceCertificatePath": "<path-to-your-service-certificate>.pfx",
    "IdentityProviderCertificatePath": "<path-to-the-mpass-idp-certificate>.cer",
    "IdentityProviderIssuer": "<MPass IdP metadata EntityID>",
    "SamlLoginDestination": "https://<mpass-host>/login/saml",
    "SamlLogoutDestination": "https://<mpass-host>/logout/saml"
  }
}
```

* `SamlRequestIssuer` -> your application's issuer. Assertions from MPass must name it as their audience.
* `SamlServiceLoginDestination`, `SamlServiceLogoutDestination`, `SamlServiceSingleLogoutDestination` -> your URLs where MPass posts the login response, the logout response and the external logout request.
* `ServiceCertificatePath` -> your service certificate (PFX with your private key).
* `IdentityProviderCertificatePath` -> the IdP certificate (CER with the MPass public key).
* `IdentityProviderIssuer` -> the EntityID from the IdP metadata the agency gives you.
* `SamlLoginDestination`, `SamlLogoutDestination` -> the MPass login and logout URLs the agency gives you.

Keep the PFX and CER files out of source control.

The password for the service certificate (PFX) is required too, but it doesn't belong in this file. Load it from any configuration source, for example from user-secrets or the environment variable `MPassSamlOptions__ServiceCertificatePassword`. Without it the service certificate isn't loaded and the host won't start.

```
dotnet user-secrets set "MPassSamlOptions:ServiceCertificatePassword" "<your-pfx-password>"
```

Relative certificate paths are resolved against the process working directory, not against the content root or the output folder. Absolute paths save you some confusion here.

When the host starts, the library checks these settings and loads the certificates. If something is wrong, it stops with one `OptionsValidationException` that lists every problem at once, so you can fix them in one pass. The full option list with defaults and allowed values is in the [usage guide](docs/usage.md).

<hr/>

## Register the service

```csharp
using MPassHelperDotNet.XDependencyInjection;

// Startup.ConfigureServices
services.AddMPassService(Configuration);

// or Program.cs with minimal hosting
builder.Services.AddMPassService(builder.Configuration);

// optional: certificate health check, registered under the name "MPass"
services.AddHealthChecks().AddMPassCertificateHealthCheck();
```

Then inject `IAuthMPassService` where you need it. The login and logout flows are described step by step in the [usage guide](docs/usage.md).

<hr/>

## Upgrading from 1.x

Version 2.0 is a breaking release. Result types now come from `RzR.ResultMessage.Abstractions`, `IdentityProviderIssuer` is a new required setting, and options are validated when the host starts. Each change and what to do about it is listed in [Upgrading from 1.x](docs/usage.md#upgrading-from-1x).

<hr/>

## Content
1. [USING](docs/usage.md)
2. [CHANGELOG](docs/CHANGELOG.md)
3. [BRANCH-GUIDE](docs/branch-guide.md)
