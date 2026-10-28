# Builds and tests the middleman inside the Visual Studio developer environment.
# vswhere finds nothing on this machine, so vcvars64.bat is located by searching the disk.
param([string]$Task = "build")
$vcvars = Get-ChildItem 'C:\Program Files\Microsoft Visual Studio' -Filter vcvars64.bat -Recurse -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $vcvars) { Write-Error "vcvars64.bat not found"; exit 1 }
switch ($Task) {
    "build"   { $cmd = "cargo build --release" }
    "test"    { $cmd = "cargo test --release" }
    default   { $cmd = "cargo $Task" }
}
cmd /c "`"$vcvars`" >nul && $cmd"
exit $LASTEXITCODE
