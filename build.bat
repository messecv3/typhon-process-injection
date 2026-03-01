@echo off
setlocal

:: ============================================================================
:: Typhon Build Script
:: ============================================================================
:: Requires: Visual Studio 2019+ with C++ desktop workload, Windows SDK
:: Usage: build.bat [debug|release]
:: ============================================================================

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=release

echo.
echo  Typhon Build (%CONFIG%)
echo  ========================
echo.

:: Find Visual Studio
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2^>nul`) do set "VSINSTALL=%%i"
if not defined VSINSTALL (
    echo [-] Visual Studio not found. Install VS with C++ desktop workload.
    exit /b 1
)

:: Find MSVC
for /f "tokens=*" %%i in ('dir /b /ad /o-n "%VSINSTALL%\VC\Tools\MSVC" 2^>nul') do (
    set "MSVCVER=%%i"
    goto :msvc_ok
)
echo [-] MSVC toolchain not found
exit /b 1
:msvc_ok

set "TOOLDIR=%VSINSTALL%\VC\Tools\MSVC\%MSVCVER%\bin\Hostx64\x64"

:: Find Windows SDK
set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
for /f "tokens=*" %%i in ('dir /b /ad /o-n "%SDKROOT%\Include" 2^>nul ^| findstr "^10\."') do (
    set "SDKVER=%%i"
    goto :sdk_ok
)
echo [-] Windows SDK not found
exit /b 1
:sdk_ok

:: Environment
set "INCLUDE=%VSINSTALL%\VC\Tools\MSVC\%MSVCVER%\include;%SDKROOT%\Include\%SDKVER%\ucrt;%SDKROOT%\Include\%SDKVER%\um;%SDKROOT%\Include\%SDKVER%\shared"
set "LIB=%VSINSTALL%\VC\Tools\MSVC\%MSVCVER%\lib\x64;%SDKROOT%\Lib\%SDKVER%\ucrt\x64;%SDKROOT%\Lib\%SDKVER%\um\x64"

set "CL_EXE=%TOOLDIR%\cl.exe"
set "ML64_EXE=%TOOLDIR%\ml64.exe"
set "LINK_EXE=%TOOLDIR%\link.exe"

:: Paths
set "SRC=%~dp0src"
set "INC=%~dp0include"
set "BLD=%~dp0build"

if not exist "%BLD%" mkdir "%BLD%"

:: Compiler flags
if /i "%CONFIG%"=="debug" (
    set "CFLAGS=/nologo /c /EHsc /W3 /std:c++17 /Od /Zi /MTd /D_DEBUG /DDEBUG_BUILD=1"
    set "LFLAGS=/DEBUG:FULL"
) else (
    set "CFLAGS=/nologo /c /EHsc /W3 /std:c++17 /O2 /GL /MT /DNDEBUG /D_DEBUG /DDEBUG_BUILD=1"
    set "LFLAGS=/LTCG /OPT:REF /OPT:ICF"
)

set "CFLAGS=%CFLAGS% /I"%INC%""

:: Compile C++ sources
echo [*] Compiling...
for %%f in ("%SRC%\*.cpp") do (
    echo     %%~nxf
    "%CL_EXE%" %CFLAGS% /Fo"%BLD%\%%~nf.obj" "%%f" >nul 2>&1
    if errorlevel 1 (
        echo [-] Failed: %%~nxf
        "%CL_EXE%" %CFLAGS% /Fo"%BLD%\%%~nf.obj" "%%f"
        exit /b 1
    )
)

:: Assemble
echo     syscall_stub.asm
"%ML64_EXE%" /nologo /c /Fo"%BLD%\syscall_stub.obj" "%SRC%\syscall_stub.asm" >nul 2>&1
if errorlevel 1 (
    echo [-] Failed: syscall_stub.asm
    exit /b 1
)

:: Link
echo.
echo [*] Linking...
"%LINK_EXE%" /nologo "%BLD%\*.obj" kernel32.lib user32.lib advapi32.lib /OUT:"%BLD%\typhon.exe" /SUBSYSTEM:CONSOLE %LFLAGS% /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA >nul 2>&1
if errorlevel 1 (
    echo [-] Link failed
    "%LINK_EXE%" /nologo "%BLD%\*.obj" kernel32.lib user32.lib advapi32.lib /OUT:"%BLD%\typhon.exe" /SUBSYSTEM:CONSOLE %LFLAGS% /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA
    exit /b 1
)

echo.
echo [+] Build successful: build\typhon.exe
for %%f in ("%BLD%\typhon.exe") do echo [+] Size: %%~zf bytes
echo.

endlocal
