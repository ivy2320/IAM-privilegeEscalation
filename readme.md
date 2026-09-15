# AWS IAM Privilege Escalation & Defense

A hands-on cloud security project simulating realistic AWS IAM
misconfigurations, exploiting them as an attacker would, then detecting
and remediating each one — built to demonstrate practical understanding
of least-privilege design and common privilege escalation patterns.

## Why this project

Most IAM misconfigurations aren't exotic — they come from convenience-driven
permission grants that nobody scoped down. This project recreates 7
distinct root causes of AWS privilege escalation inside a small simulated
organization, attacks each one from the compromised user's own limited
credentials, and documents detection + remediation for each.

## Environment overview

| User | Organizational Role | Injected Vulnerability | Risk Category |
|---|---|---|---|
| `admin-k` | IT/Security Admin | None (baseline) | Safe |
| `dev-t` | Developer (read-only) | None (baseline) | Safe |
| `dev-w` | Developer (deployment) | `iam:PassRole` on `Resource: "*"` | Resource-scoping failure (confused deputy) |
| `qa-a` | QA / Test policy management | `iam:CreatePolicyVersion` on self-attached policy | Self-referential escalation |
| `ex-helpdesk` | Legacy support account | `iam:SetDefaultPolicyVersion` (stale version rollback) | Historical/version-based risk |
| external contractor | Temporary external access | `iam:AttachUserPolicy` on self | Direct self-grant escalation |
| `automator-r` + `role-automation-task` | Automation/CI bot | Overly broad trust policy (`Principal: root`) | Trust-boundary failure |

## Project phases

1. **Build** — construct the vulnerable environment above (console + IAM)
2. **Attack** — simulate each escalation via AWS CLI, using only the
   compromised user's own scoped credentials
3. **Detect** — identify each attack's fingerprint in CloudTrail
4. **Fix** — apply scoped policies/permission boundaries, re-attempt the
   attack, and confirm it now fails

## Status

| # | Vulnerability | Attack | Detection | Fix |
|---|---|---|---|---|
| 1 | qa-a self-escalation | ✅ Complete |✅ Complete  | ✅ Complete  |
| 2 | ex-helpdesk version rollback | ⬜ Pending | ⬜ Pending | ⬜ Pending |
| 3 | external contractor self-grant | ⬜ Pending | ⬜ Pending | ⬜ Pending |
| 4 | automator-r trust policy | ⬜ Pending | ⬜ Pending | ⬜ Pending |
| 5 | dev-w PassRole confused deputy | ⬜ Pending | ⬜ Pending | ⬜ Pending |

See [`attack-simulations/`](./attack-simulations) for detailed PoC writeups
of each vulnerability, including exact commands and output.


## Disclaimer

All resources exist in a personal, non-production AWS account created
solely for this research. No real organizational data or production
systems were involved.
