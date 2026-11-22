# windows-cis-hardening
Lab-tested CIS Windows 11 hardening with PowerShell and LGPO, including assessment, verification and rollback.

CIS WINDOWS 11 STANDALONE v5.0.0 - LEVEL 1, SECTION 9.3 DEMO

PURPOSE
This example implements CIS Level 1 settings in section 9.3 on a standalone Windows 11 machine. It is not the full CIS baseline.

PACKAGE (3 FILES)
- Invoke-CIS-W11-L1-Public-FW-Demo.ps1
- LGPO.exe
- README.txt

REQUIREMENTS
- Standalone Windows 11 VM, 64-bit Windows PowerShell 5.1
- Put all three files in C:\CIS (or a similar alternative folder).
- Apply and Rollback require PowerShell launched as Administrator.
- Apply/Rollback refuse domain joined and Entra joined devices. Do not use on centrally managed devices.

SETTINGS THIS SCRIPT CONFIGURES - PUBLIC FIREWALL PROFILE ONLY
9.3.1  Enable Windows Firewall (On).
9.3.2  Default inbound connections: Block.
9.3.3  Disable blocked-inbound notifications.
9.3.4  Use %SystemRoot%\System32\LogFiles\Firewall\publicfw.log.
9.3.5  Firewall log maximum size: 16384 KB.
9.3.6  Log dropped packets: Yes.
9.3.7  Log successful connections: Yes.
The script changes local policy for the Public profile, not individual firewall allow rules or the Domain/Private profile settings.

INSTRUCTIONS:
Open PowerShell and select the folder:

cd C:\CIS

If execution is blocked, use:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

This is temporary for the current PowerShell process. It is not a permanent policy change.

1. ASSESS [Administrator not required; read-only]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Assess

2. PLAN [Administrator not required; read-only]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Plan

3. TEST LGPO [Administrator not required; writes test files only]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode TestLGPO -OutputRoot "$env:TEMP\CIS-Section9.3-Validation"

4. APPLY [Administrator required; modifies local policy]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Apply -Approved
  
Apply creates an LGPO backup and prints a Run directory. Copy run directory path

5. VERIFY [Administrator NOT required; read-only]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Verify

6. ROLLBACK IF NECESSARY [Administrator REQUIRED; modifies local policy]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Rollback -Approved -RunDirectory 'paste_run_directory_path_from_step_4_output'

7. REASSESS [Administrator NOT required; read-only]
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Assess
