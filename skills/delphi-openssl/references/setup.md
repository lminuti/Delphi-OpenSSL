# Setup and library loading

## Deploying libcrypto

Only `libcrypto` is needed (`libssl` is not loaded).

| OpenSSL | Windows 32-bit | Windows 64-bit | Linux |
|---------|----------------|----------------|-------|
| 4.x | `libcrypto-4.dll` | `libcrypto-4-x64.dll` | `libcrypto.so.4` |
| 3.x | `libcrypto-3.dll` | `libcrypto-3-x64.dll` | `libcrypto.so.3` |
| 1.1.x | `libcrypto-1_1.dll` | `libcrypto-1_1-x64.dll` | `libcrypto.so.1.1` |
| 1.0.x | `libeay32.dll` | `libeay32.dll` | `libcrypto.so.1.0.0` |

On Windows put the DLL next to the EXE, in a directory set via `OpenSSLPath`, or in the system search path.

## Default search order

`GetOpenSSLLoader.SSLLibVersions` is a `;`-separated list of file names (without `.dll` on Windows) tried in order:

- Win32: `libcrypto-4;libcrypto-3;libcrypto-1_1;libeay32`
- Win64: `libcrypto-4-x64;libcrypto-3-x64;libcrypto-1_1-x64;libeay32`
- Linux: `libcrypto.so.4;libcrypto.so.3;libcrypto.so.1.1;libcrypto.so.1.0.0`

`GetOpenSSLLoader.OpenSSLPath` is the directory to search (empty = system search path). It is initialized from the `OPENSSL_LIBRARY_PATH` environment variable.

## Forcing a specific version / folder

Do it **before** the first crypto object is created (e.g. in the `.dpr` or in an `initialization` section):

```delphi
uses
  OpenSSL.Api, OpenSSL.Core;

begin
  GetOpenSSLLoader.OpenSSLPath := ExtractFilePath(ParamStr(0)) + 'openssl';
  if not LoadOpenSSLLibrary('libcrypto-3-x64') then   // overrides SSLLibVersions
    raise Exception.Create('OpenSSL 3 not found');
  Writeln(OpenSSLName, ' ', OpenSSLVersion);         // e.g. "OpenSSL 3.0.13 ..." / "3.0.13"
end.
```

- `LoadOpenSSLLibrary(const ASSLLibVersions: string = ''): Boolean` — non-empty argument replaces `SSLLibVersions`; empty keeps the current list. Returns `False` (does not raise) if nothing loads. Calling it again when already loaded is cheap.
- `UnLoadOpenSSLLibrary` — unloads and clears all function pointers. To switch version at runtime: unload, set the list, load again (no crypto objects must be alive).
- `OpenSSLVersion` → version number only (`'3.0.13'`); `OpenSSLName` → full banner.
- `GetOpenSSLLoader.VersionNum` → numeric `OPENSSL_VERSION_NUMBER` (e.g. `$30000000` and above for 3.x).
- `GetOpenSSLLoader.IsLoaded`, `GetOpenSSLLoader.FailedToLoad` (`TStringList` of optional symbols not found in the loaded library — useful for diagnostics; those entry points stay `nil`).

## Packages / project setup

- Delphi XE7 → 12+ (Win32, Win64, Linux64).
- Either install `Packages/<DelphiVersion>/OpenSSL.dproj` or add the `Source` folder to the project search path. Required units: `OpenSSL.Api`, `OpenSSL.Core` plus the feature units you use.

## Typical startup diagnostics

```delphi
if not LoadOpenSSLLibrary then
  ShowMessage('libcrypto not found. Searched: ' + GetOpenSSLLoader.SSLLibVersions +
    ' in "' + GetOpenSSLLoader.OpenSSLPath + '"')
else if GetOpenSSLLoader.FailedToLoad.Count > 0 then
  Log('Missing optional OpenSSL symbols: ' + GetOpenSSLLoader.FailedToLoad.CommaText);
```
