> **Note** This repository is developed using .netstandard2.0, .netstandard2.1, net5.0+

[![NuGet Version](https://img.shields.io/nuget/v/MPassHelperDotNet.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/MPassHelperDotNet/)
[![Nuget Downloads](https://img.shields.io/nuget/dt/MPassHelperDotNet.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/MPassHelperDotNet)


One important reason for developing this repository is to quickly implement the governmental authentication service  provided by [e-governance agency](https://egov.md/), named `MPass`, available in the Republic of Moldova.<br/>

<p align="center">
    <a href="https://mpass.gov.md">
        <img src="assets/mpass.png"/>
    </a>
</p>

<br/>

Proceed to the service portal where you can read more about them by clicking [here](https://mpass.gov.md).

The current repository appears as a result of several implementations in projects from scratch, losing a lot of time and desire for a more easy way of implementation in new projects.
This repository is a wrapper for the currently available service. Using a few configuration parameters from the application settings file `appsettings.json`, you may implement them very easily into your own application.<br/>
Using the wrapper you will no longer be forced to install the application certificate on the current machine/server.
<br/>

Available configuration settings are: 
* `IdentityProviderCertificatePath` -> Auth service provider certificate path (file with *.cer at the end);
* `ServiceCertificatePath` -> Client/application certificate path (file with *.pfx at the end);
* `ServiceCertificatePassword` -> Client/application certificate password.

Above was represented a few parameters, for more details, and a whole list of parameters and more information about that, follow the info from using doc.

**In case you wish to use it in your project, u can install the package from <a href="https://www.nuget.org/packages/MPassHelperDotNet" target="_blank">nuget.org</a>** or specify what version you want:

> `Install-Package MPassHelperDotNet -Version x.x.x.x`

## Content
1. [USING](docs/usage.md)
1. [CHANGELOG](docs/CHANGELOG.md)
1. [BRANCH-GUIDE](docs/branch-guide.md)