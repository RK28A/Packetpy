# PacketPy setup for Windows (editing / management side).
# The packet datapath runs in the Linux kernel on the Raspberry Pi; Windows is
# used to write and compile-check scripts and to run the control panels.
# Run from PowerShell:   .\setup\windows.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) {
  Write-Host "Python 3 is not installed. Get it from https://www.python.org/downloads/ (tick 'Add to PATH')." -ForegroundColor Yellow
  exit 1
}

& $py.Source (Join-Path $root "setup\scaffold.py")

Write-Host ""
Write-Host "To run the panels locally (no packet datapath on Windows):" -ForegroundColor Cyan
Write-Host "    python agent\packetpyd.py"
Write-Host "Then open http://localhost:8080"
Write-Host ""
Write-Host "To actually modify packets, deploy on the Raspberry Pi with ./install.sh," -ForegroundColor Cyan
Write-Host "then open http://packetpy.local:8080 from this PC."
