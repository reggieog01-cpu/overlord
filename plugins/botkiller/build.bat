@echo off
setlocal enabledelayedexpansion

set "PLUGIN_DIR=%~dp0."
if not "%~1"=="" set "PLUGIN_DIR=%~1"

set "NATIVE_DIR=%PLUGIN_DIR%\native"
set "PLUGIN_NAME=botkiller"
set "ZIP_OUT=%PLUGIN_DIR%\%PLUGIN_NAME%.zip"

if not exist "%NATIVE_DIR%\Cargo.toml" (
  echo [error] native\Cargo.toml not found in %NATIVE_DIR%
  exit /b 1
)

REM Build targets - default to windows-amd64 on Windows
if not defined BUILD_TARGETS set "BUILD_TARGETS=windows-amd64"

set "BUILT_FILES="
for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )

  if "!TARGET_OS!"=="windows" (
    set "EXT=dll"
    set "RUST_TARGET=x86_64-pc-windows-msvc"
    if "!TARGET_ARCH!"=="arm64" set "RUST_TARGET=aarch64-pc-windows-msvc"
  ) else (
    echo [error] botkiller is Windows-only; skipping %%T
    goto :continue
  )

  set "OUTFILE=%PLUGIN_DIR%\%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.!EXT!"

  echo [build] cargo build --release --target=!RUST_TARGET! in %NATIVE_DIR%
  pushd "%NATIVE_DIR%"
  cargo build --release --target=!RUST_TARGET!
  if errorlevel 1 (
    echo [error] build failed for !TARGET_OS!-!TARGET_ARCH!
    popd
    exit /b 1
  )
  popd

  copy /Y "%NATIVE_DIR%\target\!RUST_TARGET!\release\botkiller.dll" "!OUTFILE!" >nul
  if errorlevel 1 (
    echo [error] copy failed for !TARGET_OS!-!TARGET_ARCH!
    exit /b 1
  )
  set "BUILT_FILES=!BUILT_FILES! '%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.!EXT!'"

  :continue
)

if exist "%ZIP_OUT%" del /f /q "%ZIP_OUT%"

set "ZIP_SOURCES='%PLUGIN_DIR%\config.json'"
for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )
  if "!TARGET_OS!"=="windows" (
    if exist "%PLUGIN_DIR%\%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.dll" (
      set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%\%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.dll'"
    )
  )
)

if exist "%PLUGIN_DIR%\%PLUGIN_NAME%.html" set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%\%PLUGIN_NAME%.html'"
if exist "%PLUGIN_DIR%\%PLUGIN_NAME%.css" set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%\%PLUGIN_NAME%.css'"
if exist "%PLUGIN_DIR%\%PLUGIN_NAME%.js" set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%\%PLUGIN_NAME%.js'"

powershell -NoProfile -Command "Compress-Archive -Path !ZIP_SOURCES! -DestinationPath '%ZIP_OUT%'"
if errorlevel 1 (
  echo [error] zip failed
  exit /b 1
)

echo [ok] %ZIP_OUT%
