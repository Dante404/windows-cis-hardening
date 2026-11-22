# CIS Windows 11 hardening - PowerShell and LGPO example

A lab-tested example of **controlled CIS Benchmark implementation** on a standalone Windows 11 device. The PowerShell script assesses existing settings, plans changes, applies a scoped Local Group Policy delta through Microsoft's LGPO utility, verifies the result, and supports targeted rollback.

**Scope:** CIS Microsoft Windows 11 Stand-alone Benchmark **v5.0.0**, **Level 1**, **Section 9.3 - Public Firewall Profile** (seven recommendations). This is **not** a complete CIS Level 1 or Level 2 baseline, a production deployment package, or a guarantee of application compatibility.

## Approach

CIS hardening is not one-size-fits-all. Identify the system's purpose, existing controls, management authority, network connectivity, and application dependencies before selecting settings. Applying an entire policy template may be quick, but doing so without compatibility testing can disrupt services and applications. This example demonstrates a sequential approach:

**Assess -> Plan -> Validate LGPO -> Backup and Apply -> Verify -> Functional test -> Rollback (if necessary)**

## Repository contents

| Item | Purpose |
| --- | --- |
| [`Invoke-CIS-W11-L1-Public-FW-Demo.ps1`](Invoke-CIS-W11-L1-Public-FW-Demo.ps1) | Self-contained assessment, policy generation, apply, verification, and rollback logic |
| [`evidence/Validation-Summary.md`](evidence/Validation-Summary.md) | Actual Windows 11 VM test results and console screenshots |

**External prerequisite:** Download **LGPO.exe** from Microsoft's [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) and place it beside the script. LGPO.exe is **not included in this repository**. No separate policy template or mapping CSV is required; the script generates the LGPO input and rollback files when needed.

## What the script configures

All changes are scoped to the **Windows Defender Firewall Public profile**. The script does not add firewall allow rules or directly change the Private or Domain profile.

| CIS Level 1 recommendation | Policy target |
| --- | --- |
| 9.3.1 Firewall state | On |
| 9.3.2 Inbound connections | Block by default (subject to existing allow rules) |
| 9.3.3 Blocked-inbound notifications | Disabled |
| 9.3.4 Firewall log file name | Configured `.log` path |
| 9.3.5 Firewall log size | At least 16,384 KB |
| 9.3.6 Log dropped packets | Enabled |
| 9.3.7 Log successful connections | Enabled |

For **9.3.4**, this demo chooses `%SystemRoot%\System32\LogFiles\Firewall\publicfw.log` to keep a separate Public-profile log. **CIS does not require that specific filename.** Plan labels this as optional log-path standardization, even when the existing path already meets the CIS recommendation.

## Prerequisites and safeguards

- A **standalone Windows 11 lab VM**, 64-bit Windows PowerShell 5.1, and Microsoft's LGPO.exe.
- **Administrator privileges** for Apply and Rollback; Assess, Plan, Verify, and TestLGPO do not require elevation when their output paths are writable.
- Apply and Rollback refuse domain-joined and Entra-joined devices. This is **not** an exhaustive check for all central management or MDM configurations. Do not use on centrally managed systems.
- Use a recoverable **VM snapshot** before Apply. The LGPO backup and targeted rollback files are useful, but they are not a full system restore.
- Test access, connectivity, and application behavior after hardening. A CIS policy check alone cannot establish operational compatibility.

## Running the example

Save the script and LGPO.exe to the same directory (shown here as `C:\CIS`). Open **Windows PowerShell 5.1**:

```powershell
cd C:\CIS
```

If a lab machine blocks script execution, use this command **only when permitted by local security policy**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

This changes execution policy only for the current PowerShell process; closing the session removes the change. It does not override policies enforced by Group Policy. Do not bypass organization-managed script controls.

### 1. Assess (read-only, no administrator required)

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Assess
```

Shows the effective value, CIS target, compliance result, and whether the setting is explicitly configured in local policy.

### 2. Plan (read-only, no administrator required)

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Plan
```

Shows exactly which values would be corrected, which already-correct defaults would be enforced, and whether the log path would be standardized. **Nothing is applied.**

### 3. Test LGPO syntax (no administrator required with writable output)

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode TestLGPO -OutputRoot "$env:TEMP\CIS-Section9.3-Validation"
```

Generates, compiles, and parses policy text without importing it. Writes validation files only to the selected folder.

### 4. Apply (administrator required)

Open **Windows PowerShell as Administrator** and run:

```powershell
cd C:\CIS
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Apply -Approved
```

Apply reviews the proposed delta, saves the current local policy and rollback metadata, imports the generated policy with LGPO.exe, refreshes computer policy, and verifies the result. **Preserve the printed `Run directory` path** for rollback. The policy refresh can also update other applicable computer policies.

### 5. Verify (read-only, no administrator required)

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Verify
```

Checks both the effective Windows Firewall values and the explicit local policy values. Then independently test the device's required network and application behavior.

### 6. Roll back if needed (administrator required)

Use the **actual** run directory printed during step 4:

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Rollback -Approved -RunDirectory 'C:\ProgramData\CIS-Section9.3-Demo\YOUR-APPLY-RUN-DIRECTORY'
```

Rollback restores the seven scoped local policy entries to their previous state and reports whether the original policy values were restored. The output is not a substitute for testing effective firewall behavior after rollback. If rollback fails, investigate rather than blindly retrying; a VM snapshot remains the recovery option.

### 7. Reassess (read-only)

```powershell
.\Invoke-CIS-W11-L1-Public-FW-Demo.ps1 -Mode Assess
```

Compare the result with the initial assessment.

## Lab validation

The workflow was tested in a standalone Windows 11 VirtualBox VM with LGPO **3.0.2004.13001** on **November 22, 2026**:

| Stage | Effective CIS targets met | Explicit local policy targets met |
| --- | ---: | ---: |
| Before Apply | 3/7 | 0/7 |
| After Apply and Verify | **7/7** | **7/7** |
| After Rollback | 3/7 | 0/7 |

All seven scoped original policy entries were reported restored, and the final reassessment matched the initial configuration. See the [validation summary and original console screenshots](evidence/Validation-Summary.md).

**Limitations:** These are lab results for one Windows 11 installation, not CIS certification or proof of compatibility with another customer's devices, drivers, applications, or management environment.