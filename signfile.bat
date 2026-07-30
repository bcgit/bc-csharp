@echo off

set BatchDir=%~dp0
set Target=%1

rem The code-signing private key is held on a hardware token (SafeNet), as required
rem for publicly-trusted code-signing certificates since June 2023. It is
rem non-exportable, so there is no .p12 to point at: the certificate is selected
rem from the Windows certificate store instead.
rem
rem By default the certificate is matched by subject name, which survives renewal.
rem To pin an exact certificate, set BC_CODESIGN_SHA1 to its SHA-1 thumbprint.
set CertSelect=/n "Legion of the Bouncy Castle Inc."
if defined BC_CODESIGN_SHA1 set CertSelect=/sha1 %BC_CODESIGN_SHA1%

set TimestampUrl=http://timestamp.comodoca.com
rem set TimestampUrl=http://timestamp.sectigo.com

rem Locate signtool.exe: use the highest installed Windows SDK version. Override by
rem setting SIGNTOOL to a full path.
rem Note: deliberately not written as a parenthesised if-block. Inside one, %SdkRoot%
rem and %SdkVer% would be expanded when the block is parsed, i.e. before the loop
rem below assigns them.
if defined SIGNTOOL goto HaveSignTool
set "SdkRoot=%ProgramFiles(x86)%\Windows Kits\10\bin"
for /f "delims=" %%I in ('dir /b /o:n "%SdkRoot%\10.*" 2^>nul') do set "SdkVer=%%I"
if defined SdkVer set "SIGNTOOL=%SdkRoot%\%SdkVer%\x64\signtool.exe"
:HaveSignTool

if not exist "%SIGNTOOL%" (
    echo ERROR: signtool.exe not found. Install the Windows SDK Signing Tools,
    echo        or set SIGNTOOL to its full path.
    exit /b 1
)

echo Preparing to sign %Target%
echo "%SIGNTOOL%" sign %CertSelect% /fd sha256 /tr "%TimestampUrl%" /td sha256 %Target%

rem Timestamp server requires 15 seconds or more between signing requests
rem When publishing need to limit parallel build tasks to 1 in Tools|Options|Projects and Solutions|Build and Run
rem (from the command line, pass -m:1 to dotnet build / msbuild)
set attempts=10
:DoWhile
    echo %attempts% attempts remaining
    echo Waiting for 30 seconds before issuing command (avoid timeserver rejection)
    ping -n 30 127.0.0.1 >NUL
    "%SIGNTOOL%" sign %CertSelect% /fd sha256 /tr "%TimestampUrl%" /td sha256 %Target% && goto EndDoWhile
    set /a attempts = %attempts% - 1
    if %attempts% gtr 0 goto DoWhile
    echo ERROR: failed to sign %Target%
    exit /b 1
:EndDoWhile

"%SIGNTOOL%" verify /pa /tw %Target%
