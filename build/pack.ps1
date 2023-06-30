$asCfg = $args[0]
if ($asCfg -eq 'Release')
{
	$assemblyInfo = (Get-Content ..\shared\GeneralAssemblyInfo.cs);
	$finalVerion = '1.0.0.0';
	$nugetPath = "../../nuget"
	
	$assemblyInfoVerion = ($assemblyInfo -match 'AssemblyInformationalVersion')
	$assemblyInfoVerion = $assemblyInfoVerion -split ('"')
	$assemblyInfoVerion = $assemblyInfoVerion[1]
	
	$assemblyVersion = ($assemblyInfo -match 'AssemblyVersion\(".*"\)')
	$assemblyVersion = $assemblyVersion -split ('"')
	$assemblyVersion = $assemblyVersion[1]
	
	if ($assemblyInfoVerion -eq ' ' -or $assemblyInfoVerion -eq '' -or $assemblyInfoVerion.EndsWith(".*")) { $finalVerion = $assemblyVersion; }
	else { $finalVerion = $assemblyVersion + '-' + $assemblyInfoVerion; }
	
	dotnet pack -p:PackageVersion=$finalVerion --no-build -c Release --output $nugetPath
}
else { Write-Host "Solution not in 'Release' mode. Received:" $asCfg }
