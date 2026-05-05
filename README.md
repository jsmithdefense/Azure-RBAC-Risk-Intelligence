# Azure RBAC Risk Intelligence

Azure environments accumulate RBAC assignments over time. Role names are vague, assignments are scattered across subscriptions, and no native tooling tells you which identities carry the greatest risk, why, and what to do about it.

**Enumerate, score, and remediate overprivileged identities across your Azure tenant.**

---

Sample Finding:

> test-service-principal can create, modify, and delete virtually any Azure resource within Azure subscription 1 - including virtual machines, storage accounts, databases, and networking components - without needing to involve a human operator.
>
> It can deploy new infrastructure or exfiltrate data by spinning up compute resources, copying storage blobs, or creating outbound network paths, making it a high-value target if its credentials are compromised.
>
> — AI-generated summary produced by this tool against a live Azure environment

---

## What It Does

- Enumerates all role assignments across every accessible subscription
- Classifies roles by what their permissions allow and at what scope they apply
- Scores principals by cumulative privilege exposure across all subscriptions
- Generates AI-powered capability summaries and prioritized remediation playbooks
- Parses AI output into executable remediations with per-action approval
- Executes approved remediations directly against your environment via the Azure SDK
- Exports a professional PDF report suitable for stakeholder review
- Logs every remediation action to an audit trail before execution

---

## How It Works

### Role Classification
Roles are classified by their permitted `actions` & `dataActions`

| Classification | What It Means |
|---|---|
| `privilege_escalation` | Can modify access control |
| `resource_control_broad` | Can create or modify infrastructure |
| `resource_control_narrow` | Controls a specific service domain |
| `data_access` | Can read or extract stored data |
| `security_visibility` | Can view monitoring or security telemetry |
| `read_only` | Limited to metadata inspection |

### Cumulative Risk Scoring
Principal risk is the sum of all assignment scores across all subscriptions. This surfaces identities that accumulate significant privilege through multiple lower-severity assignments.

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

### Quiet Mode (AI summaries and principal details written to PDF report only)
```bash
python -m src.main --quiet
```

---

## Sample Output

### Subscription & Tenant Summary
```
TENANT-LEVEL RISK SUMMARY
==========================================================================================
Subscriptions analyzed: 1
Assigned roles: 2
Unique Assignments: 2

SUBSCRIPTION RISK RANKING
==========================================================================================
Rank   Subscription                                  Risk Score   Assignments   Principals
------------------------------------------------------------------------------------------
1      Azure subscription 1                          130          2             2
```

### Role Classification
```
Role                                          Classification               Reason
------------------------------------------------------------------------------------------
Owner                                         privilege_escalation         *
Contributor                                   resource_control_narrow      *
```

### Principal Risk Analysis
```
Name = Studying Security | Type = User | Severity = High | Score = 75 | Assignments = 1 | Riskiest Role = Owner
  - High | 75 | Owner | Action = * | Classification = privilege_escalation | Scope = subscription (subscription) | Sub = ...eb88716d

Name = test-service-principal | Type = ServicePrincipal | Severity = Medium | Score = 55 | Assignments = 1 | Riskiest Role = Contributor
  - Medium | 55 | Contributor | Action = * | Classification = resource_control_narrow | Scope = subscription (subscription) | Sub = ...eb88716d
```

### AI Capability Summary
```
`test-service-principal` can create, modify, and delete virtually any Azure resource within Azure subscription 1 - including virtual machines, storage accounts, databases, and networking components - without needing to involve a human operator.
  - It can deploy new infrastructure or exfiltrate data by spinning up compute resources, copying storage blobs, or creating outbound network paths, making it a high-value target if its credentials are compromised. 
  - It can modify or delete existing application workloads, disrupt services, or tamper with diagnostic/logging configurations, potentially blinding security monitoring across the subscription.
  - It cannot manage Azure AD/Entra ID identities or grant access to other principals (no Owner or User Access Administrator rights), limiting lateral movement via RBAC - but resource-level abuse potential remains broad.
  - A compromised or misconfigured service principal with subscription-wide Contributor is a persistent, non-expiring foothold that operates silently under an automated identity, making detection harder than with human accounts.
```
### Remediation Playbook
```
1. [CRITICAL | Effort: Medium] Scope Down the Contributor Assignment to Required Resource Groups Only

   Why
   Subscription-wide Contributor grants blast radius across every resource in Azure
   subscription 1; limiting scope to only the resource groups test-service-principal
   legitimately needs dramatically reduces damage potential from credential compromise.

   Steps
     1. Navigate to Azure Portal → Subscriptions → Azure subscription 1 → Access control (IAM)
     2. Locate the Contributor assignment for test-service-principal and click Remove
     3. Navigate to each required resource group → Access control (IAM) → Add role assignment
     4. Assign Contributor scoped only to those resource groups

   Validation
   az role assignment list --assignee <principal-id> \
     --scope /subscriptions/<subscription-id>
   Confirm no subscription-level Contributor assignment is returned.

-> Generated 4 structured remediation action(s).
```

### Remediation Engine
```
REMEDIATION ENGINE
==========================================================================================
  Principal: Studying Security (User)
    1. [CRITICAL | Effort: Low]    Convert Permanent Owner Assignment to PIM Eligible         (convert_to_pim_eligible)
    2. [CRITICAL | Effort: Medium] Scope Down to Least-Privilege Role at Resource Group Level (remove_role_assignment)
    3. [HIGH     | Effort: Low]    Enable MFA and Conditional Access for the Account          (manual_review_required)
    4. [HIGH     | Effort: Low]    Enable Alerting on Owner-Level Role Assignment Changes     (manual_review_required)

  Principal: test-service-principal (ServicePrincipal)
    5. [CRITICAL | Effort: Medium] Scope Down the Contributor Assignment to Required Resource Groups Only  (remove_role_assignment)
    6. [HIGH     | Effort: Medium] Replace Broad Contributor with a Custom Role               (manual_review_required)
    7. [HIGH     | Effort: Low]    Rotate Service Principal Credentials and Audit Recent Activity  (manual_review_required)
    8. [MEDIUM   | Effort: Low]    Enable Diagnostic Logging and Alerting                     (manual_review_required)

Select actions to execute (comma-separated numbers, 0=all, S=skip): 4,5
```

### Per-Action Approval
```
About to: [HIGH] Enable Alerting on Owner-Level Role Assignment Changes  (manual_review_required)
  Principal: Studying Security
Execute this remediation? [y/N]: y

  Manual review required: Create an Azure Monitor activity log alert rule scoped to
  Azure subscription 1 that triggers on Microsoft.Authorization/roleAssignments/write
  events, with an action group configured to notify the security team.
  Result: MANUAL — logged to audit file.

About to: [CRITICAL] Scope Down the Contributor Assignment to Required Resource Groups Only  (remove_role_assignment)
  Principal: test-service-principal
  Role:      Contributor
  Scope:     /subscriptions/9d006e44-79bc-473e-afa6-1aa9eb88716d
Execute this remediation? [y/N]: y

  Result: SUCCESS — assignment removed and validated.
```

### Summary & Audit Trail
```
REMEDIATION SUMMARY
==========================================================================================
  Succeeded:      1
  Failed:         0
  Manual/skipped: 1
  Audit log:      reports/remediation_audit_20260329_142506.json
```

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

#### ⚠️ Disclaimer

The remediation playbooks generated by this tool are produced by an AI model and have 
not been independently verified. Role assignment changes in Azure can be irreversible 
and may affect production workloads, access controls, and business-critical systems.

**Before executing any remediation (manual / automated) .. you are responsible for:**

- Reviewing the proposed change and its blast radius
- Confirming the principal and scope are correctly identified
- Validating the recommended role aligns with least-privilege requirements in your environment
- Ensuring changes are approved through your organisation's change management process

The author accepts no liability for changes made to your Azure environment 
as a result of acting on AI-generated output.

---
