# ForensiX V4.5 — Initial Detection Rules

This document specifies the technical design, declarative definitions, factual detection semantics, and forensic boundaries of the **Initial Detection Rules (`src/forensix/initial_rules.py`)** implemented in **ForensiX V4.5 (Event Correlation & Rule-Based Detection)**.

---

## 1. Purpose

Milestone V4.5 introduces the first canonical catalog of declarative, explainable, and deterministic detection rules in ForensiX. These rules formalize specific multi-event behavioural patterns observed in digital forensics and incident response.

Key objectives:
- **Observational forensic patterns**: Rules identify explicit sequences of observed evidence. Detection is strictly **NOT** proof of compromise, intrusion, attacker activity, or malicious intent.
- **Strictly declarative**: Rules are data structures (`DetectionRule`, `RuleCondition`), strictly prohibiting executable callbacks, lambdas, `eval()`, `exec()`, or dynamic expressions.
- **Non-speculative language**: Descriptions use objective, factual observations ("Observed ... within ... seconds") and reject interpretive claims ("confirmed attack", "system compromised").
- **Deterministic provenance**: Every rule ID is derived deterministically via RFC 4122 UUIDv5.
- **Direct V4.4 compatibility**: Rules are consumed directly by the existing V4.4 `DetectionEngine`.

---

## 2. Architectural Position

```
V1 & V2 Host Forensics (Filesystem, Logs, Auth, Accounts, Persistence)
                              │
                              ▼
V3 Timeline Reconstruction (TimelineEvent, ReconstructedTimeline)
                              │
                              ▼
V4.2 Correlation Engine (Discovers explicit relationships)
                              │
                              ▼
V4.1 Correlation Model (Correlation, CorrelationCollection)
                              │
                              ▼
V4.3 Detection Rule Model (DetectionRule, RuleCondition, RuleCollection)
                              │
                              ▼
V4.4 Detection Engine (DetectionEngine, evaluate_rule, evaluate_rules)
                              │
                              ▼
V4.5 Initial Detection Rules (The 4 canonical declarative rules)
                              │
                              ▼
DetectionResult Objects (Factual, deterministic, explainable matches)
                              │ [FUTURE MILESTONES]
                              ▼
                    V4.6 Detection Reporting
                    V4.7 CLI & Triage Integration
                    V4.8 Final Testing & Hardening
```

---

## 3. Initial Rule Inventory

The V4 specification defines four initial forensic detection patterns:

| Rule # | Name | Rule ID | Category Requirements | Event Type Requirements | Relationship Requirements | Time Window |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Rule 1** | SSH Authentication Followed by Sudo | `RULE-e4957412-2337-5242-881a-81deb75f505c` | `authentication` | `ssh_login_success`, `sudo_command` | `AUTHENTICATION_PRIVILEGE` | `300.0s` |
| **Rule 2** | Repeated Failed SSH Attempts Followed by Successful SSH Login | `RULE-ece7e718-eb79-5259-89c9-5536d162b539` | `authentication` | `ssh_login_failure`, `ssh_login_success` | None | `300.0s` |
| **Rule 3** | Account Activity Followed by Privilege Activity | `RULE-af73ddf6-4fe1-5ea5-ad9c-087e5c11304a` | `account`, `authentication` | `user_added`, `sudo_command` | None | `300.0s` |
| **Rule 4** | Persistence Modification Following Authentication or Privilege | `RULE-1d218f52-160a-5581-8ee1-3f0f36ae40bf` | `authentication`, `persistence` | `sudo_command`, `cron_job_scheduled` | None | `300.0s` |

---

## 4. Detailed Rule Specifications

### 4.1 Rule 1: Successful SSH Login Followed by Sudo

- **Intent**: Identifies a successful SSH authentication event immediately followed by privileged command execution via `sudo` by the same identity or source within a narrow temporal window.
- **Factory**: `create_ssh_auth_sudo_rule(time_window_seconds=300.0)`
- **Event Categories**: `(TimelineCategory.AUTHENTICATION,)`
- **Event Types**: `("ssh_login_success", "sudo_command")`
- **Required Relationships**: `(RelationshipType.AUTHENTICATION_PRIVILEGE,)`
- **Time Window**: `300.0` seconds (inclusive boundary: $\text{delta} \le 300.0\text{s}$)
- **Description**:
  > "Identifies a successful SSH authentication event followed by privileged sudo command execution by the same identity within the configured time window."
- **Detection Description**:
  > "Observed a successful SSH authentication followed by privileged sudo execution for the same identity within 300 seconds."
- **Evaluation Mechanism**: The rule specifies `required_relationships=[RelationshipType.AUTHENTICATION_PRIVILEGE]`. V4.4 `DetectionEngine` matches against `Correlation` objects discovered by V4.2, verifying identity alignment, event types, categories, and duration.

### 4.2 Rule 2: Repeated Failed SSH Attempts Followed by Successful SSH Login

- **Intent**: Identifies authentication failure activity immediately preceding a successful authentication within a defined window.
- **Factory**: `create_repeated_ssh_failure_success_rule(time_window_seconds=300.0)`
- **Event Categories**: `(TimelineCategory.AUTHENTICATION,)`
- **Event Types**: `("ssh_login_failure", "ssh_login_success")`
- **Required Relationships**: None (multi-event temporal sequence)
- **Time Window**: `300.0` seconds
- **Description**:
  > "Identifies failed SSH authentication attempts followed chronologically by a successful SSH authentication within the configured time window."
- **Detection Description**:
  > "Observed failed SSH authentication attempts followed by a successful SSH authentication within 300 seconds."
- **Model Limitation & Design Rationale**:
  - The V4.3 declarative rule model represents `required_event_types` as a sequence of distinct event types (deduplicated as a frozen tuple).
  - The declarative model does not feature custom executable counting loops, numeric recurrence quantifiers (e.g. `COUNT(failure) >= 5`), or dynamic script expressions, as these violate the zero-code-execution forensic principle.
  - Consequently, Rule 2 models the core temporal sequence: an `ssh_login_failure` observation followed chronologically by `ssh_login_success` within the time window. When multiple failures precede a success, each distinct failure-to-success transition within the window is deterministically matched.

### 4.3 Rule 3: Account Activity Followed by Privilege-Related Activity

- **Intent**: Identifies account provisioning or modification activity followed by privileged command escalation within the configured window.
- **Factory**: `create_account_privilege_rule(time_window_seconds=300.0, account_event_type="user_added", privilege_event_type="sudo_command")`
- **Event Categories**: `(TimelineCategory.ACCOUNT, TimelineCategory.AUTHENTICATION)`
- **Event Types**: `("user_added", "sudo_command")`
- **Required Relationships**: None
- **Time Window**: `300.0` seconds
- **Description**:
  > "Identifies account configuration or creation activity followed by privilege-related command execution within the configured time window."
- **Detection Description**:
  > "Observed account activity followed by privilege-related activity within 300 seconds."
- **Evaluation Mechanism**: Evaluated by V4.4 `DetectionEngine` as a multi-event sequence across the `account` and `authentication` categories.

### 4.4 Rule 4: Persistence Modification Following Authentication or Privilege Activity

- **Intent**: Identifies privileged activity or authentication followed by persistence mechanism modifications (such as scheduled tasks or cron configurations) within the configured window.
- **Factory**: `create_persistence_followup_rule(time_window_seconds=300.0, trigger_event_type="sudo_command", persistence_event_type="cron_job_scheduled")`
- **Event Categories**: `(TimelineCategory.AUTHENTICATION, TimelineCategory.PERSISTENCE)`
- **Event Types**: `("sudo_command", "cron_job_scheduled")`
- **Required Relationships**: None
- **Time Window**: `300.0` seconds
- **Description**:
  > "Identifies authentication or privilege activity followed by persistence configuration modification within the configured time window."
- **Detection Description**:
  > "Observed authentication or privilege activity followed by persistence configuration modification within 300 seconds."
- **Evaluation Mechanism**: Evaluated by V4.4 `DetectionEngine` as a multi-event sequence transitioning from `authentication` to `persistence`.

---

## 5. Rule Collection & Engine Consumption

The initial rules are organized into an immutable, deterministically ordered `RuleCollection`:

```python
from forensix import create_initial_rules, get_initial_rules, DetectionEngine

# Instantiate initial rules
rules = get_initial_rules()  # RuleCollection with 4 rules

# Evaluate via V4.4 DetectionEngine
engine = DetectionEngine(rules=rules)
results = engine.evaluate(timeline=timeline_events, correlations=correlations)
```

### Deterministic Rule Ordering
`create_initial_rules()` always produces rules in exact sequential order:
1. Index 0: `SSH Authentication Followed by Sudo` (`RULE-e4957412-...`)
2. Index 1: `Repeated Failed SSH Attempts Followed by Successful SSH Login` (`RULE-ece7e718-...`)
3. Index 2: `Account Activity Followed by Privilege Activity` (`RULE-af73ddf6-...`)
4. Index 3: `Persistence Modification Following Authentication or Privilege` (`RULE-1d218f52-...`)

---

## 6. Forensic Integrity & Non-Speculative Policy

### Why Detections Are Not Compromise Verdicts
A rule match signifies that an observed forensic pattern occurred within the specified timeframe. In a benign enterprise or administrative context:
- System administrators legitimately SSH into a host and execute `sudo` commands (Rule 1).
- Users occasionally mistype passwords before successfully authenticating (Rule 2).
- Provisioning scripts legitimately create service accounts and configure administrative roles (Rule 3).
- System maintenance jobs configure cron tasks or systemd units (Rule 4).

Therefore, ForensiX strictly refrains from asserting:
- "System compromised"
- "Attacker confirmed"
- "Brute-force attack detected"
- "Confirmed intrusion"

The output of V4.5 is factual pattern discovery intended to accelerate triage for human forensic examiners.

---

## 7. Limitations & Explicit Scope Boundaries

- **Milestone Boundary**: V4.5 implements ONLY the Initial Detection Rules definitions and collection factories.
- **Not Included**:
  - V4.6 Reporting (JSON/HTML detection reporting formats)
  - V4.7 CLI & Triage Integration
  - V4.8 Final Testing & Hardening
  - Threat intelligence lookups, machine learning heuristics, or automated remediation.
- **Evidence Safety**: All tests run against synthetic timelines. Zero modifications to evidence files.
