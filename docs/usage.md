> :point_up: From the beginning let's make clear one moment. It is a wrapper for interoperability service connection provided by [e-governance agency](https://egov.md/). If you accessed this repository and already installed it or you want or install the package, and you already contacted the agency and discussed that and obtained the necessary information for clean implementation. :muscle:

<br/>

In curret wrapper is available method:
* `GenerateAuthRequestAsync` -> Generate auth/login request data.
* `GetUserDataFromAuthResponseAsync` -> Get/read user auth details from SAMLResponse variable.
* `GenerateLogoutRequestAsync` -> Generate logout request.
* `ValidateLogoutResponseAsync` -> Validate logout response (SAMLResponse).
* `ProcessExternalLogoutRequestAsync` -> Process external logout requests and responses with details which must be sent to the service provider.
* `PingAsync` -> Check if service is alive.

For more details, please check the documentation obtained from the responsible authorities where you can find all the smallest details necessary for the implementation and understanding of the working flow.
<br/>
<hr/>

**Configure the application settings file**

In case you use `netstandard2.0`, `netstandard2.1`, `net5`, `netcoreapp3.1` in your project find a settings file like `appsettings.json` or `appsettings.env.json` and complete it with the following parameters.
```json
  "MPassSamlOptions": {
    "SamlRequestIssuer": "https://host.name",
    "SamlServiceLoginDestination": "https://host.name/mpass-login",
    "SamlServiceLogoutDestination": "https://host.name/mpass-logout",
    "SamlServiceSingleLogoutDestination": "https://host.name/mpass-slo",
    "ServiceCertificatePath": "host.name.pfx",
    "ServiceCertificatePassword": "p@ssw0rd",
    "IdentityProviderCertificatePath": "mpass.cer",
    "SamlMessageTimeout": "00:10:00",
    "SamlLoginDestination": "https://MPassHostName.md/login/saml",
    "SamlLogoutDestination": "https://MPassHostName.md/logout/saml"
  }
```

* `SamlRequestIssuer` -> Current service address(public URL);
* `SamlServiceLoginDestination` -> Current service auth URL (where will be sent auth response);
* `SamlServiceLogoutDestination`-> Current service logout URL (where will be sent logout response);
* `SamlServiceSingleLogoutDestination` -> Current service logout(external request) URL (where will be sent logout request);
* `ServiceCertificatePath` -> Provide service certificate, the path with filename (PFX certificate);
* `ServiceCertificatePassword` -> Provide the password to the service certificate specified upper.
* `IdentityProviderCertificatePath` -> Identity provider auth service certificate public key (CER);
* `SamlMessageTimeout` -> Service message timeout;
* `SamlLoginDestination` -> Auth service provider login/auth URL (where to push auth request);
* `SamlLogoutDestination` -> Auth service provider logout URL (where to push logout request/response);

<hr/>

**Calling the service**

In case of using the `netstandard2.0+` in your project, after adding configuration data, you must set dependency injection for using functionality. In your project in the file `Startup.cs` add the following part of the code:
```csharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddMPassService(Configuration);
    
    ...
}
```

The next step is to add an injection in your authentication controller.
```csharp
public class AuthController : ResultBaseApiController
{
    private readonly IAuthMPassService _authMPassService;
    
    public AuthController(IAuthMPassService authMPassService)
        => _authMPassService = authMPassService;
        
        ...
}
```

The next step is to implement login/logout methods as you identify the best way in your project.

`PingAsync` method will allow you to check if the SSO service is alive and you can connect.

#### In conclusion, a small summary of how to use and how interact with defined methods.

When the user tries to initiate `MPass` authentication you must call `GenerateAuthRequestAsync`. 

As a result, you receive:
* `HTML document` (this document must be posted to auth service provider, in other words, execute it);
* And generated auth request id (`AuthRequestId` you must save it). Auth id is required on validation when you receive auth response from the service provider.

After the user redirection to the service auth page, and auth proceed with success, the user must be redirected to `SamlServiceLoginDestination` (specified in app settings).
On implemented route (auth response) you must call `GetUserDataFromAuthResponseAsync`. The specified method will be validated request with the response and as success validation you receive user auth details, then do your auth logic and set the user auth session. Received `SessionIndexId` must be saved in the current user session.

<hr/>

When the user tries to initiate logout from the current system (if the user is authenticated with `MPass`), you must call `GenerateLogoutRequestAsync` and populate with necessary logout information like: 
* `SessionIndexId` -> saved on user authentication;
* `RelayState`
* `UserIdentifierId` -> User identification code (IDNP);

As a result, you receive:
* `HTML document` (this document must be posted to the authentication service provider, in other words, execute it);
* And generated logout request id (`LogOutRequestId` you must save it). A logout request id is required on validation when you receive a logout response from the service provider.

After successful logout from the service provider, the authentication service will post data (logout response) to the `SamlServiceLogoutDestination` URL defined in your application settings. On implemented route (logout response) you must call `ValidateLogoutResponseAsync` which will validate the logout response (if the user tries to log out from the current system). 
In case the previously defined method returns a successful result, you must log out the user from the current system/remove/invalidate the user session.

<hr/>

Another case that must be completed is a logout request when a logout process is initiated from the authentication service provider or another service (which is connected to SSO).

To complete this case, you must implement a route that allows you to receive logout requests from auth service provider. The route (URL) to single logout must be stored in app settings in the variable `SamlServiceSingleLogoutDestination`. This parameter will be known to be a service provider (where tu post log out request). When some request is received you must call `ProcessExternalLogoutRequestAsync`, this method will process logout data and generate a logout response that must be sent to auth service provider.

As a result, you receive:
* `HTML document` (this document must be posted to log out service provider, in other words, execute it);
* And generated logout response id (`LogoutResponseId`).

In case the previously defined method returns a successful result, you must log out the user from the current system/remove/invalidate the user session. After this execute the logout response.

<div style='page-break-after: always'></div>

Another feature implemented in current warper is health check of auth service and certificates. to use it, you must add a small sequence of code.
In your project in the file `Startup.cs` add the following part of the code:
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