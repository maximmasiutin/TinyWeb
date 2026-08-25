# Container lane: build the Win32 server and CGI fixtures on this Windows
# host, then run the whole suite inside a Wine container (Linux containers
# mode in Docker). See TESTS/README.md.
param(
    [string]$Fpc = $env:FPC
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Fpc) { $Fpc = 'fpc' }

& $Fpc -B -MObjFPC (Join-Path $repo 'SRC\Tiny.dpr')
if ($LASTEXITCODE -ne 0) { throw 'server build failed' }

$env:FPC = $Fpc
python (Join-Path $PSScriptRoot 'build_fixtures.py')
if ($LASTEXITCODE -ne 0) { throw 'fixture build failed' }

docker build -t tinyweb-tests -f (Join-Path $PSScriptRoot 'Dockerfile') $PSScriptRoot
if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }

docker run --rm -v "${repo}:/work" -w /work -e TINYWEB_WINE=1 `
    tinyweb-tests python3 -m pytest TESTS -m 'not slow'
exit $LASTEXITCODE
