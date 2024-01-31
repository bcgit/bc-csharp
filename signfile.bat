@echo off

set BatchDir=%~dp0
set Target=%1

set CodesignFile=%BatchDir%BC_codesign.p12
set PasswordFile=%BatchDir%BC_password.txt
set TimestampUrl=http://timestamp.comodoca.com
rem set TimestampUrl=http://timestamp.sectigo.com
set /p CodesignPass=<"%PasswordFile%"

rem TODO Figure out how to locate this automatically, or somehow use the developer command prompt
set SignToolDir=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\
set SignTool=%SignToolDir%signtool.exe

echo Preparing to sign %Target%
echo "%SignTool%" sign /f "%CodesignFile%" /fd sha256 /tr "%TimestampUrl%" /td sha256 /p PASSWORD %Target

rem Timestamp server requires 15 seconds or more between signing requests
rem When publishing need to limit parallel build tasks to 1 in Tools|Options|Projects and Solutions|Build and Run
set attempts=10
:DoWhile
    echo %attempts% attempts remaining
    echo Waiting for 30 seconds before issuing command (avoid timeserver rejection)
    ping -n 30 127.0.0.1 >NUL
    "%SignTool%" sign /f "%CodesignFile%" /fd sha256 /tr "%TimestampUrl%" /td sha256 /p "%CodesignPass%" %Target% && goto EndDoWhile
    set /a attempts = %attempts% - 1
    if %attempts% gtr 0 goto DoWhile
:EndDoWhile

"%SignTool%" verify /pa /tw %Target%
