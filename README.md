# Azure RBAC Risk Analyzer

**Enumerate, score, and remediate overprivileged identities across your Azure tenant.**

No third-party platforms. No agents. No connectors. Just the Azure SDK and the Anthropic API running against your control plane. Understand your enviorment with AI-enriched summaries, custom remediation playbooks, and autonomous remediation execution.

---
Sample Finding:

> *"The analysts group can actively manage Microsoft Sentinel incidents and alerts in the production SOC resource group — including dismissing, closing, or modifying incident status — actions that could suppress legitimate detections or obscure attacker activity."*
>
> — AI-generated summary produced by this tool against a live Azure environment

---

## What It Does

Azure environments accumulate RBAC assignments over time. Role names are opaque, assignments are scattered across subscriptions, and no native tooling tells you which identities represent the greatest real-world risk — or what to do about it.

This tool:
- Enumerates all role assignments across every accessible subscription
- Classifies roles by what permissions allow and at what scope thry apply
- Scores principals by cumulative privilege exposure across all subscriptions
- Generates AI-powered capability summaries and prioritized remediation playbooks
- Parses AI output into executable remediations with per-action approval
- Executes approved remediations directly against your environment via the Azure SDK
- Exports a professional PDF report suitable for stakeholder review
- Logs every remediation action to an audit trail before execution
---

## Quick Start

### Prerequisites
- Python 3.12+
- Azure CLI (`az login`)
- `Reader` role at subscription scope
- Microsoft Graph read permissions for principal name resolution
- Anthropic API key (optional — required for AI enrichment only)

### Install
```bash
git clone https://github.com/jsmithdefense/Azure-RBAC-Risk-Analyzer
cd Azure-RBAC-Risk-Analyzer

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
az login
```

Uses `DefaultAzureCredential`. Resolves to your Azure CLI session in local environments. No credentials are stored.

### Run
```bash
python -m src.main
```

### With AI Enrichment
```bash
export ANTHROPIC_API_KEY=your_key_here
python -m src.main
```

---

## Sample Output

### Subscription & Tenant Summary
```
TENANT-LEVEL RISK SUMMARY
==========================================================================================
Subscriptions analyzed: 1
Assigned roles: 3
Unique Assignments: 3

SUBSCRIPTION RISK RANKING
==========================================================================================
Rank   Subscription                                  Risk Score   Assignments   Principals
------------------------------------------------------------------------------------------
1      Azure subscription 1                          160          3             1
```

### Role Classification
```
Assigned roles:

Role                                          Classification               Reason
------------------------------------------------------------------------------------------
Owner                                         privilege_escalation         *
Security Admin                                privilege_escalation         *
Reader                                        read_only                    /read
```

### Principal Risk Analysis

```
Name = Studying Security | Type = User | Severity = Critical | Score = 160 | Assignments = 3 | Riskiest Role = Owner
  - High | 75 | Owner          | Action = * | Classification = privilege_escalation | Scope = subscription (subscription)   | Sub = ...eb88716d
  - High | 65 | Security Admin | Action = * | Classification = privilege_escalation | Scope = rbac-test-rg (resource_group) | Sub = ...eb88716d
  - Low  | 20 | Reader         | Action = /read | Classification = read_only        | Scope = rbac-test-rg (resource_group) | Sub = ...eb88716d
```

### AI Capability Summary
```
- As a subscription-level Owner, Studying Security has unrestricted control over every
  resource in the subscription — they can create, modify, delete, and reconfigure any
  service, including storage accounts, virtual machines, databases, and networking
  infrastructure.

- They can grant or revoke any Azure RBAC role to any principal at subscription scope,
  meaning they could silently elevate another account (or a compromised identity) to
  Owner-level access, making lateral movement and persistence trivial.

- The Security Admin role on rbac-test-rg grants the ability to manage Microsoft Defender
  for Cloud policies, dismiss security alerts, and modify security configurations — allowing
  an attacker to blind the organization's threat detection while operating within that
  resource group.

- Combined, these assignments create a critical privilege escalation path: the principal
  can weaponize Owner rights to create backdoor identities, exfiltrate data, or destroy
  resources across the entire subscription with no technical barriers.
```

### Remediation Playbook
```
1. [CRITICAL | Effort: Low] Remove Permanent Subscription-Level Owner Assignment

   Why
   A permanent, always-active Owner role at subscription scope gives Studying Security
   unrestricted access to all resources and the ability to manipulate RBAC for every
   principal in Azure subscription 1.

   Steps
     1. Navigate to Azure Portal → Subscriptions → Azure subscription 1 → Access control (IAM)
     2. Filter by role Owner and locate the assignment for Studying Security
     3. Select the assignment and click Remove, then confirm removal

   Validation
   az role assignment list --assignee <principal-id> \
     --scope /subscriptions/<subscription-id> --role Owner
   Confirm the command returns an empty array.

-> Generated 4 structured remediation action(s).
```

### Remediation Engine
```
REMEDIATION ENGINE
==========================================================================================
  Principal: Studying Security (User)
    1. [CRITICAL | Effort: Low]    Remove Permanent Subscription-Level Owner Assignment      (remove_role_assignment)
    2. [CRITICAL | Effort: Medium] Convert Owner Access to PIM Just-in-Time Eligible Assignment  (convert_to_pim_eligible)
    3. [CRITICAL | Effort: Low]    Remove Security Admin Role from rbac-test-rg              (remove_role_assignment)
    4. [LOW      | Effort: Low]    Remove Redundant Reader Role from rbac-test-rg            (remove_role_assignment)

Select actions to execute (comma-separated numbers, 0=all, S=skip): 3,4

About to: [CRITICAL] Remove Security Admin Role from rbac-test-rg  (remove_role_assignment)
  Principal: Studying Security
  Role:      Security Admin
  Scope:     /subscriptions/.../resourceGroups/rbac-test-rg
Execute this remediation? [y/N]: y
  Result: SUCCESS — assignment removed and validated.

About to: [LOW] Remove Redundant Reader Role from rbac-test-rg  (remove_role_assignment)
  Principal: Studying Security
  Role:      Reader
  Scope:     /subscriptions/.../resourceGroups/rbac-test-rg
Execute this remediation? [y/N]: y
  Result: SUCCESS — assignment removed and validated.

REMEDIATION SUMMARY
==========================================================================================
  Succeeded:      2
  Failed:         0
  Manual/skipped: 0
  Audit log:      reports/remediation_audit_20260328_003954.json
```

## How It Works

### Role Classification
Roles are classified by what their permissions actually allow — not just their names. A custom role containing `*/write` permissions gets flagged regardless of what it's called.

| Classification | What It Means |
|---|---|
| `privilege_escalation` | Can modify access control |
| `resource_control_broad` | Can create or modify infrastructure |
| `resource_control_narrow` | Controls a specific service domain |
| `data_access` | Can read or extract stored data |
| `security_visibility` | Can view monitoring or security telemetry |
| `read_only` | Limited to metadata inspection |

### Cumulative Risk Scoring
Principal risk is the sum of all assignment scores across all subscriptions — not just the highest single role. This surfaces identities that accumulate significant privilege through multiple lower-severity assignments.

### AI Enrichment
Select which principals to analyze, choose your model, review the estimated cost before confirming. Each enriched principal gets a plain-English capability summary and a prioritized remediation playbook with **Why**, **Steps**, and **Validation** for each action.

### Remediation Engine
AI output is parsed into structured, machine-executable actions. Each action is presented for individual approval, logged to an audit file, executed via the Azure SDK, and validated.

| Action Type | Behavior |
|---|---|
| `remove_role_assignment` | Executes removal via Azure SDK, validates success |
| `convert_to_pim_eligible` | Provides step-by-step PIM instructions |
| `manual_review_required` | Logs description for human execution |

---

## Required Permissions

| Permission | Purpose |
|---|---|
| `Reader` at subscription scope | RBAC enumeration |
| `Microsoft.Graph` read access | Principal name resolution |
| `Microsoft.Authorization/roleAssignments/delete` | Remediation execution |

---

## Project Structure
```
Azure-RBAC-Risk-Analyzer/
├── src/
│   ├── main.py                    # Pipeline orchestration
│   ├── rbac_collector.py          # Azure RBAC enumeration
│   ├── role_taxonomy_generator.py # Capability inference
│   ├── risk_model.py              # Cumulative scoring
│   ├── scope_utils.py             # Scope normalization
│   ├── ai_enrichment.py           # AI analysis and remediation parsing
│   ├── report_writer.py           # JSON report generation
│   ├── pdf_report.py              # PDF report generation
│   ├── remediation_engine.py      # Azure SDK execution engine
│   ├── models.py                  # Data structures
│   └── config_loader.py           # Configuration management
├── config/
│   └── role_taxonomy.json         # Role capability classifications
├── reports/                       # Generated reports (gitignored)
└── requirements.txt
```

---

## Roadmap

- [x] Multi-subscription RBAC enumeration and tenant-level aggregation
- [x] Capability-based role classification with analyst override taxonomy
- [x] Cumulative principal risk scoring across subscriptions
- [x] Subscription risk ranking
- [x] Structured JSON report output
- [x] Interactive AI enrichment with model selection and cost estimation
- [x] AI capability summaries with prioritized remediation playbooks
- [x] PDF report export
- [x] Remediation engine with per-action approval and audit logging
- [ ] Post-remediation PDF report mapping identified risks to executed actions with security posture delta summary
- [ ] Privilege escalation path detection

---

