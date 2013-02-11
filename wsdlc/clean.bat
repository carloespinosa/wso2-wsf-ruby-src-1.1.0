@echo off

@call vcvars32.bat /nologo

@echo Cleaning WSDLC...

@cd build\win32

@if exist int.msvc rmdir /q int.msvc

nmake clean

@echo Cleaned!

@cd ..\..



