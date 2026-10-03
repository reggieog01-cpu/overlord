@echo off
setlocal enabledelayedexpansion

set "PLUGIN_DIR=%~dp0."
if not "%~1"=="" set "PLUGIN_DIR=%~1"

set "NATIVE_DIR=%PLUGIN_DIR%\native"
set "PLUGIN_NAME=vmon"
set "ZIP_OUT=%PLUGIN_DIR%\%PLUGIN_NAME%.zip"

if not exist "%NATIVE_DIR%\Cargo.toml" (
  echo [error] native\Cargo.toml not found in %NATIVE_DIR%
  exit /b 1
)

echo [build] cargo build --release --target=x86_64-pc-windows-msvc in %NATIVE_DIR%
pushd "%NATIVE_DIR%"
cargo build --release --target=x86_64-pc-windows-msvc
if errorlevel 1 (
  echo [error] build failed
  popd
  exit /b 1
)
popd

copy /Y "%NATIVE_DIR%\target\x86_64-pc-windows-msvc\release\vmon.dll" "%PLUGIN_DIR%\vmon-windows-amd64.dll" >nul
if errorlevel 1 (
  echo [error] dll copy failed
  exit /b 1
)

if exist "%ZIP_OUT%" del /f /q "%ZIP_OUT%"

powershell -NoProfile -Command "Compress-Archive -Path '%PLUGIN_DIR%\config.json','%PLUGIN_DIR%\server.js','%PLUGIN_DIR%\vmon-windows-amd64.dll','%PLUGIN_DIR%\vmon.html','%PLUGIN_DIR%\vmon.css','%PLUGIN_DIR%\vmon.js' -DestinationPath '%ZIP_OUT%' -Force"
if errorlevel 1 (
  echo [error] zip failed
  exit /b 1
)

echo [ok] %ZIP_OUT%
