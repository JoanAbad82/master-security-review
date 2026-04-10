# Compilation from source

Project file:

src/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher.csproj

Solution file:

src/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher.slnx

Compile from PowerShell on Windows:

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe
& $msbuild "src/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher.csproj" /p:Configuration=Debug

Expected Debug output:

src/MasterSecurityReviewLauncher/MasterSecurityReviewLauncher/bin/Debug/MasterSecurityReviewLauncher.exe

Note: bin/ and obj/ are ignored by git.

This documents compilation from source only, not an official downloadable release.
