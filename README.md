# Azure RBAC Risk Intelligence

Azure environments accumulate RBAC assignments over time. Role names are vague, assignments are scattered across subscriptions, and no native tooling tells you which identities carry the greatest risk, why, and what to do about it.

**Enumerate, score, and remediate overprivileged identities across your Azure tenant.**

> [!WARNING]
> The role classification has 8 known defects, and the scores are not validated. Read [Known Issues](#known-issues) before you use the results.

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

## AI Enrichment: Bring Your Own Model

AI enrichment is **optional** and **provider-agnostic**. The analyzer speaks the
OpenAI-compatible chat completions protocol, so it works with any hosted provider
or any local inference server. Three settings select the endpoint — nothing else
changes:

| Setting | Env var | Example |
|---|---|---|
| Endpoint | `LLM_BASE_URL` | `https://openrouter.ai/api/v1` |
| Model | `LLM_MODEL` | `z-ai/glm-5.2` |
| Credential | `LLM_API_KEY` | omit for most local servers |

Defaults live in `config/llm.json`; environment variables override them. **API keys
are read from the environment only** and are never written to that file.

### Run it entirely locally

To keep your RBAC data on your own network, point it at a local server:

```bash
# Ollama
ollama serve
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_MODEL=qwen3:14b

# LM Studio — start the server from the Developer tab
export LLM_BASE_URL=http://localhost:1234/v1

# llama.cpp
llama-server -m model.gguf --port 8080
export LLM_BASE_URL=http://localhost:8080/v1
```

No API key is needed. `config/llm.json` contains presets for these and for vLLM,
OpenAI, and Anthropic's compatibility endpoint.

### What leaves your machine

Be precise about this. The analyzer **must** reach `management.azure.com` and
`graph.microsoft.com` — that is how it reads your RBAC configuration. It is not a
no-network tool.

What AI enrichment adds is a request to whatever endpoint you configure,
containing principal names, role names, and scope paths for the principals you
select. With a local `base_url`, that request never leaves your network. The tool
prints the endpoint and whether it is local before sending anything, and asks for
confirmation.

Skip enrichment entirely (enter `S` at the selection prompt) and no LLM endpoint
is contacted at all.

### Why the model returns JSON

The model is asked for structured JSON, and the analyzer renders all human-readable
output itself. This keeps the prompt small — which matters for local models with
limited context — makes parsing deterministic, and means output formatting does not
depend on the model's formatting discipline. Priorities are sorted and malformed
fields are normalized in code, so a smaller model degrades gracefully instead of
breaking the report.

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

## Known Issues

An audit on 2026-09-19 found 9 defects in the role classification and the scoring. Commit `8c1de93` corrected 1 defect. 8 defects are open.

The scores are not validated. Do not use them as a final risk ranking. Examine each finding before you approve a remediation.

| # | Defect | Result |
|---|---|---|
| 1 | The classifier finds no provider family in the wildcard action `*`. | `Contributor` gets `resource_control_narrow` (20). `Tag Contributor` gets `resource_control_broad` (35). At subscription scope, a user with `Tag Contributor` scores 60 (High). A user with `Contributor` scores 45 (Medium). |
| 2 | The classifier does not read `notActions` or `notDataActions`. | `notActions` is the only difference between `Owner` and `Contributor`. `Owner` is correct only because it is in `ROLE_NAME_OVERRIDES`. |
| 3 | The escalation rule matches `roleassignments/read`. It does not require a write. | Permission to read role assignments gets `privilege_escalation` (50). That is the same weight as `Owner`. |
| 4 | The read-only rule requires `/read` in every action. | One support permission or one `/action` permission stops the rule. For example, `Monitoring Reader` gets `resource_control_narrow`. |
| 5 | The `data_access` rule does not examine the verb. | Read access and write access to data get the same weight (40). `Storage Blob Data Reader` and `Storage Blob Data Contributor` get the same score. |
| 6 | The classifier counts each `/action` permission as a write. | `listKeys/action` returns storage account keys, but the classifier puts it in `resource_control_narrow`, not with data access. |
| 7 | The broad rule counts 3 or more provider families with write access. | The count measures the length of the role definition, not the risk. `Tag Contributor` passes the rule with its deployment, alert and support permissions. |
| 8 | The severity thresholds are for one assignment, but the tool applies them to the cumulative score. | Several small assignments add up to `Critical`. One assignment to a user has a maximum score of 75, so a user is never `Critical` from one assignment. |

### Plan

Each correction changes the scores. Thus the new scores must agree with known correct results. A Terraform test lab will supply identities with known access. The defects will be corrected after that lab is ready.

---

## Quick Start

### Prerequisites
- Python 3.12+
- Azure CLI (`az login`)
- `Reader` role at subscription scope
- Microsoft Graph read permissions for principal name resolution
- An OpenAI-compatible LLM endpoint (optional — required for AI enrichment only). Any provider or a local model; see **AI Enrichment: Bring Your Own Model** below.

### Install
```bash
git clone https://github.com/jsmithdefense/Azure-RBAC-Risk-Intelligence
cd Azure-RBAC-Risk-Intelligence

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
export LLM_BASE_URL=https://openrouter.ai/api/v1   # or http://localhost:11434/v1
export LLM_MODEL=z-ai/glm-5.2                      # or your local model name
export LLM_API_KEY=your_key_here                   # omit for most local servers
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

## MCP Server

The analyzer is also exposed as an [MCP](https://modelcontextprotocol.io) server, so an
AI agent can query your RBAC posture directly. Three tools, all **read-only** — the
server cannot modify Azure.

| Tool | Purpose |
|---|---|
| `azure_rbac_analyze` | Full analysis: tenant summary, subscription risk ranking, role classifications, ranked principals |
| `azure_rbac_get_high_risk` | The riskiest principals by cumulative privilege |
| `azure_rbac_explain_role` | What a given role can actually do, with its full permission set |

It also exposes one resource:

| Resource | Purpose |
|---|---|
| `azure-rbac://taxonomy` | The closed set of capability classifications, each with its meaning and risk weight, ordered most to least severe |

The classification vocabulary is published in the server instructions and the tool
descriptions as well as the resource. This is deliberate: a client that only ever sees
one classification at a time will invent plausible-sounding categories that do not
exist, so the closed set travels with every handshake.

### Install

```bash
pip install fastmcp
```

### Run

```bash
python run_mcp_server.py
```

The server speaks MCP over **stdio**. Use `run_mcp_server.py` rather than
`src/mcp_server.py` directly: the module uses package-relative imports, and the
launcher pins the repo root onto `sys.path` so the command works from any
working directory.

### Authentication

Uses the same `DefaultAzureCredential` as the CLI, so `az login` is all that is
required. No credentials are stored or passed as arguments. `Reader` at
subscription scope and Microsoft Graph read access are enough — the server never
requests write permissions.

### Register with an MCP client

```json
{
  "mcp": {
    "azure-rbac": {
      "type": "local",
      "command": [
        "/absolute/path/to/.venv/bin/python",
        "/absolute/path/to/run_mcp_server.py"
      ],
      "enabled": true,
      "timeout": 60000
    }
  }
}
```

On Windows the interpreter is `.venv/Scripts/python.exe`. `timeout` here is the
handshake timeout, not a per-call timeout — raise it so the Azure SDK import has
room to load on startup.

### Debugging

```bash
npx @modelcontextprotocol/inspector python run_mcp_server.py
```

### Notes

- **AI enrichment is off.** The MCP tools never call the Anthropic API, so no key
  is needed and no token cost is incurred. AI enrichment remains available in the CLI.
- **`azure_rbac_analyze` takes 30-120 seconds** on a real tenant. It emits progress
  notifications while it runs.
- **Remediation is deliberately not exposed.** Write actions stay in the CLI, behind
  per-action human approval.

---

## Project Structure
```
Azure-RBAC-Risk-Intelligence/
├── src/
│   ├── main.py                    # Pipeline orchestration
│   ├── rbac_collector.py          # Azure RBAC enumeration
│   ├── role_taxonomy_generator.py # Capability inference
│   ├── risk_model.py              # Cumulative scoring
│   ├── scope_utils.py             # Scope parsing and display names
│   ├── ai_enrichment.py           # AI analysis and remediation parsing
│   ├── report_writer.py           # JSON report generation
│   ├── pdf_report.py              # PDF report generation
│   ├── remediation_engine.py      # Azure SDK execution engine
│   ├── models.py                  # Data structures
│   ├── config_loader.py           # Configuration management
│   ├── llm_client.py              # Provider-agnostic OpenAI-compatible client
│   ├── build_taxonomy.py          # Regenerates config/role_taxonomy.json
│   ├── analysis_api.py            # Headless, non-interactive analysis API
│   └── mcp_server.py              # MCP server (three read-only tools)
├── run_mcp_server.py              # MCP server launcher (cwd-independent)
├── tests/
│   ├── test_scoring.py            # Scoring regression test (no Azure calls)
│   └── test_render.py             # AI output renderer contract test
├── config/
│   ├── llm.json                   # AI endpoint defaults and presets (no secrets)
│   ├── risk_weights.json          # Scoring weights and severity thresholds
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
- [x] MCP server exposing read-only analysis tools to AI agents
- [ ] Post-remediation PDF report mapping identified risks to executed actions with security posture delta summary
- [ ] Privilege escalation path detection
- [ ] Correct the 8 open defects in [Known Issues](#known-issues), verified against a test lab with known access

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
