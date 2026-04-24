@echo off
..\devcon.exe update bus.inf root\busenum
if %ERRORLEVEL% == 0 goto END
goto INSTALL

:INSTALL
..\devcon.exe install bus.inf root\busenum
goto END

:END
