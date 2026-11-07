[Setup]
AppId={{2BB2F998-E6C1-4CA7-9123-387A29CBA675}
AppName=Vigía
AppVersion=0.4.1
AppPublisher=Marc's & Co.
DefaultDirName={localappdata}\Programs\Vigia
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\out\installers
OutputBaseFilename=Vigia-0.4.1-windows-x64
UninstallDisplayIcon={app}\Vigia.exe
WizardStyle=modern
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\out\packaging\dist\Vigia\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\Vigía"; Filename: "{app}\Vigia.exe"

Name: "{userprograms}\Vigía Demo"; Filename: "{app}\Vigia.exe"; Parameters: "--demo"

[Run]
Filename: "{app}\Vigia.exe"; Description: "Abrir Vigía"; Flags: postinstall nowait skipifsilent
