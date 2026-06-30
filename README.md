# Azure Hybrid Identity & Security Monitoring Lab

Self-directed lab built from scratch in Azure. No guided walkthrough, no pre-configured environment.

---

## What This Lab Covers

| Phase | Focus |
|---|---|
| 1 | Azure foundation — resource group, VNet, budget controls |
| 2 | Active Directory domain controller on Windows Server 2025 |
| 3 | Hybrid identity sync via Microsoft Entra Connect |
| 4 | Conditional Access policy design, enforcement, and log analysis |
| 5 | Intentional misconfigurations, Sentinel detection, KQL threat hunting |

---

## Environment

| Resource | Detail |
|---|---|
| Azure Subscription | Azure for Students ($100 credit) |
| M365 Tenant | fk5xg7.onmicrosoft.com — E5 Developer (90-day) |
| Region | East US 2 |
| VM | Standard_D2s_v3, Windows Server 2025 Datacenter |
| Domain | lab.local |
| Sync | Microsoft Entra Connect — Password Hash Sync, 30-min cycle |

---

## Phase 2 — Active Directory

- Deployed Windows Server 2025 VM as domain controller
- Created domain `lab.local` with OU structure: `OU-Users`, `OU-Admins`, `OU-Workstations`
- Configured static private IP (10.0.0.4) and pointed VNet DNS at the DC
- Set NSG inbound rules, resolved dual-NSG conflict between subnet and NIC levels

---

## Phase 3 — Hybrid Identity

- Added routable UPN suffix to AD forest via PowerShell
- Corrected malformed UPNs using `Set-ADUser`
- Installed Entra Connect from entra.microsoft.com (no longer on Microsoft Download Center)
- Verified sync: `Get-ADSyncScheduler` returned `SyncCycleEnabled: True`
- All 3 users visible in Entra ID with **On-premises sync enabled: Yes**

---

## Phase 4 — Conditional Access

Three policies built and tested:

| Policy | Scope | Control |
|---|---|---|
| CA001 — Require MFA | All users / All resources | Require MFA |
| CA002 — Block Legacy Auth | All users / All resources | Block legacy clients |
| CA003 — Block Untrusted Locations | All users / All resources | Block non-trusted IPs |

Tested by signing in as synced test users via private browser. Verified enforcement through the **Conditional Access tab** in Entra sign-in logs (error code 53003).

---

## Phase 5 — Misconfigurations & Detection

### Detection Stack
- Microsoft Sentinel on Log Analytics Workspace (`law-security-lab`)
- Entra ID connector — sign-in logs + audit logs
- Azure Activity connector — resource change tracking
- Microsoft Defender for Cloud — Servers plan enabled

### Misconfigurations Introduced

**1. NSG Port Exposure**
- Created inbound rule `misconfig-inbound`: source `0.0.0.0/0`, all ports, all protocols, Allow
- Exposed domain controller to the entire internet

**2. Storage Account Public Access**
- Enabled anonymous blob access on `stlabsecurity`
- Created container `public-data` with anonymous read access

**3. MFA Bypass**
- Cleared MFA registration on `bjones`
- Excluded from CA001 and all CA policies disabled
- Successful sign-in without MFA challenge recorded

### KQL Queries Used

```kql
// NSG rule changes
AzureActivity
| where OperationNameValue contains "securityRules"
| project TimeGenerated, Caller, OperationNameValue, Properties
| order by TimeGenerated desc
```

```kql
// Storage account changes
AzureActivity
| where OperationNameValue contains "storageAccounts"
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue
| order by TimeGenerated desc
```

```kql
// Sign-ins without MFA
SigninLogs
| where UserPrincipalName contains "bjones"
| project TimeGenerated, UserPrincipalName, AuthenticationRequirement, ConditionalAccessStatus
| order by TimeGenerated desc
```

### Log Evidence — NSG Misconfiguration
```
Time:      2026-06-29 18:40:17 UTC
Actor:     kcampb67@wgu.edu
Operation: MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE
Resource:  vm-dc02-nsg/misconfig-inbound
Rule:      sourceAddressPrefix=0.0.0.0/0, destinationPortRange=*, access=Allow
```

---

## Challenges Overcome

| Challenge | Resolution |
|---|---|
| East US region blocked by Azure Policy | Moved to East US 2 |
| B/A-series VM quota restricted to 0 | Used Standard_D2s_v3 |
| Dual NSG conflict blocking RDP | Added allow rules to both subnet and NIC NSGs |
| Entra ID license page inaccessible | Used M365 Developer Program for free E5 tenant |
| UPN malformation from GUI entry | Fixed via PowerShell `Set-ADUser` |
| Entra Connect moved from Download Center | Found at entra.microsoft.com |
| Corporate network blocking port 3389 | Used Azure Bastion over HTTPS |
| Sync stopped after VM deallocation | Restarted ADSync, triggered manual delta sync |

---

## Tools Used

Active Directory · Microsoft Entra ID · Entra Connect · Conditional Access · Microsoft Sentinel · Azure Activity Log · KQL · Microsoft Defender for Cloud · Azure NSG · Azure Bastion · PowerShell
