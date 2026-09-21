{******************************************************************************}
{                                                                              }
{  Delphi OPENSSL Library                                                      }
{  Copyright (c) Luca Minuti                                                   }
{  https://bitbucket.org/lminuti/delphi-openssl                                }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}
program OpenSSL.Tests.Framework;

{$IFNDEF DEBUG}
{$IFNDEF TESTINSIGHT}
{$APPTYPE CONSOLE}
{$ENDIF}
{$ENDIF}
{$STRONGLINKTYPES ON}
uses
  System.SysUtils,
  {$IFDEF TESTINSIGHT}
  TestInsight.DUnitX,
  {$ENDIF }
  {$IFDEF DEBUG}
  DUnitX.Loggers.GUI.VCL,
  {$ENDIF }
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  DUnitX.CommandLine.Options,
  OpenSSL.Tests.Core in 'OpenSSL.Tests.Core.pas',
  OpenSSL.Tests.RandUtils in 'OpenSSL.Tests.RandUtils.pas',
  OpenSSL.Tests.RSAUtils in 'OpenSSL.Tests.RSAUtils.pas',
  OpenSSL.Tests.EncUtils in 'OpenSSL.Tests.EncUtils.pas',
  OpenSSL.Tests.SMIMEUtils in 'OpenSSL.Tests.SMIMEUtils.pas',
  OpenSSL.Tests.ReqUtils in 'OpenSSL.Tests.ReqUtils.pas',
  OpenSSL.Core in '..\Source\OpenSSL.Core.pas',
  OpenSSL.Api in '..\Source\OpenSSL.Api.pas',
  OpenSSL.EncUtils in '..\Source\OpenSSL.EncUtils.pas',
  OpenSSL.RandUtils in '..\Source\OpenSSL.RandUtils.pas',
  OpenSSL.RSAUtils in '..\Source\OpenSSL.RSAUtils.pas',
  OpenSSL.SMIMEUtils in '..\Source\OpenSSL.SMIMEUtils.pas',
  OpenSSL.ReqUtils in '..\Source\OpenSSL.ReqUtils.pas';

var
  runner : ITestRunner;
  results : IRunResults;
  logger : ITestLogger;
  nunitLogger : ITestLogger;
begin
  ReportMemoryLeaksOnShutdown := True;
  TOptionsRegistry.RegisterOption<string>('OPENSSL_VERSION', 'OV',
    procedure (AValue: string)
    begin
      OpenSSLVersionAsk := AValue;
      {$IFDEF WIN64}
      if AValue.StartsWith('4.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-4-x64'
      else if AValue.StartsWith('3.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-3-x64'
      else if AValue.StartsWith('1.1.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-1_1-x64'
      else if AValue.StartsWith('1.0.') then
        GetOpenSSLLoader.SSLLibVersions := 'libeay32';
      {$ELSE}
      if AValue.StartsWith('4.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-4'
      else if AValue.StartsWith('3.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-3'
      else if AValue.StartsWith('1.1.') then
        GetOpenSSLLoader.SSLLibVersions := 'libcrypto-1_1'
      else if AValue.StartsWith('1.0.') then
        GetOpenSSLLoader.SSLLibVersions := 'libeay32';
      {$ENDIF}
    end
  );
{$IFDEF TESTINSIGHT}
  TestInsight.DUnitX.RunRegisteredTests;
  Exit;
{$ENDIF}
{$IFDEF DEBUG}
  DUnitX.Loggers.GUI.VCL.Run;
  Exit;
{$ENDIF}
  try
    //Check command line options, will exit if invalid
    TDUnitX.CheckCommandLine;
    //Create the test runner
    runner := TDUnitX.CreateRunner;
    //Tell the runner to use RTTI to find Fixtures
    runner.UseRTTI := True;
    //tell the runner how we will log things
    //Log to the console window
    logger := TDUnitXConsoleLogger.Create(true);
    runner.AddLogger(logger);
    //Generate an NUnit compatible XML File
    nunitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    runner.AddLogger(nunitLogger);
    runner.FailsOnNoAsserts := False; //When true, Assertions must be made during tests;

    //Run tests
    results := runner.Execute;
    if not results.AllPassed then
      System.ExitCode := EXIT_ERRORS;

    {$IFNDEF CI}
    //We don't want this happening when running under CI.
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Done.. press <Enter> key to quit.');
      System.Readln;
    end;
    {$ENDIF}
  except
    on E: Exception do
      System.Writeln(E.ClassName, ': ', E.Message);
  end;
end.
