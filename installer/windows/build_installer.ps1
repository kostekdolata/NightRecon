param(
    [string]$Version = "0.45.0",
    [string]$SourceCommit = "unknown"
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Artifacts = Join-Path $Repo "artifacts\windows-installer"
$Wheels = Join-Path $Artifacts "wheels"
$BundleRoot = Join-Path $Artifacts "bundle"
$Work = Join-Path $Artifacts "pyinstaller-work"
$Spec = Join-Path $Artifacts "pyinstaller-spec"

Remove-Item $Artifacts -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Wheels,$BundleRoot,$Work,$Spec | Out-Null

python -m pip install --upgrade pip setuptools wheel build pyinstaller pyinstaller-hooks-contrib cyclonedx-bom
python -m pip install "cryptography>=50.0.1,<51" "playwright>=1.63,<2" "PyYAML>=6.0,<7" "ldap3>=2.9.1,<3" "paramiko>=5.0,<6" "impacket>=0.13.1,<0.14" "pywinrm>=0.5,<0.6" "psycopg[binary]>=3.2,<4" "mysql-connector-python>=9.0,<10"

python -m pip wheel --no-deps --no-build-isolation --wheel-dir $Wheels (Join-Path $Repo "packages\shared-core")
python -m pip wheel --no-deps --no-build-isolation --wheel-dir $Wheels (Join-Path $Repo "packages\red-engine")
python -m pip wheel --no-deps --no-build-isolation --wheel-dir $Wheels (Join-Path $Repo "packages\red-night")

$SharedWheel = (Get-ChildItem $Wheels -Filter "nightrecon_shared_core-*.whl" | Select-Object -First 1).FullName
$EngineWheel = (Get-ChildItem $Wheels -Filter "nightrecon_red_engine-*.whl" | Select-Object -First 1).FullName
$AppWheel = (Get-ChildItem $Wheels -Filter "nightrecon_red_night-*.whl" | Select-Object -First 1).FullName
if (-not $SharedWheel -or -not $EngineWheel -or -not $AppWheel) { throw "Expected Red package wheels were not built" }

python -m pip install --no-deps --force-reinstall $SharedWheel $EngineWheel $AppWheel

$Bundle = Join-Path $BundleRoot "RedNight"
python -m PyInstaller --noconfirm --clean --onedir --name RedNight --distpath $BundleRoot --workpath $Work --specpath $Spec --copy-metadata nightrecon-shared-core --copy-metadata nightrecon-red-engine --copy-metadata nightrecon-red-night --collect-submodules nightrecon_shared_core --collect-submodules nightrecon_red_engine --collect-submodules red_night_app --hidden-import yaml --hidden-import ldap3 --hidden-import paramiko --hidden-import impacket --hidden-import winrm --hidden-import psycopg --hidden-import mysql.connector --hidden-import playwright (Join-Path $PSScriptRoot "entrypoint.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed: $LASTEXITCODE" }

$PackageVersions = @{
    "nightrecon-shared-core" = (python -c "import importlib.metadata as m; print(m.version('nightrecon-shared-core'))").Trim()
    "nightrecon-red-engine" = (python -c "import importlib.metadata as m; print(m.version('nightrecon-red-engine'))").Trim()
    "nightrecon-red-night" = (python -c "import importlib.metadata as m; print(m.version('nightrecon-red-night'))").Trim()
}
$UniqueVersions = @($PackageVersions.Values | Select-Object -Unique)
if ($UniqueVersions.Count -ne 1) { throw "Red package set is mixed-version: $($PackageVersions | ConvertTo-Json -Compress)" }

$BuildInfo = @{
    schema_version = 1
    product = "Red Night"
    installer_version = $Version
    source_commit = $SourceCommit
    package_versions = $PackageVersions
    runtime = "PyInstaller onedir"
    architecture = "windows-x64"
}
$BuildInfo | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 (Join-Path $Bundle "build-info.json")

python -m cyclonedx_py environment --output-file (Join-Path $Artifacts "RedNight-$Version-sbom.json") --output-format JSON
if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed: $LASTEXITCODE" }

$Iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $Iscc) {
    choco install innosetup --no-progress -y
    $Iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
}
if ($Iscc) {
    $IsccPath = $Iscc.Source
} else {
    $Candidate = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    if (-not (Test-Path $Candidate)) { throw "Inno Setup compiler not found" }
    $IsccPath = $Candidate
}

& $IsccPath "/DMyAppVersion=$Version" "/DSourceCommit=$SourceCommit" "/DSourceDir=$Bundle" (Join-Path $PSScriptRoot "red-night.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup build failed: $LASTEXITCODE" }

$Installer = Get-ChildItem $Artifacts -Filter "RedNight-$Version-Windows-x64-Setup.exe" | Select-Object -First 1
if (-not $Installer) { throw "Installer output was not produced" }

python (Join-Path $PSScriptRoot "create_manifest.py") --installer $Installer.FullName --bundle $Bundle --wheels $Wheels --sbom (Join-Path $Artifacts "RedNight-$Version-sbom.json") --version $Version --source-commit $SourceCommit --output (Join-Path $Artifacts "RedNight-$Version-manifest.json")
if ($LASTEXITCODE -ne 0) { throw "Manifest generation failed: $LASTEXITCODE" }

Write-Host "Built $($Installer.FullName)"
