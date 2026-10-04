"""
Initial Declarative Detection Rules for ForensiX (V4.5 Initial Detection Rules).

Provides canonical, deterministic, and explainable DetectionRule definitions
representing the initial forensic detection patterns:
1. Successful SSH Login Followed by Sudo (Rule 1)
2. Repeated Failed SSH Attempts Followed by Successful SSH Login (Rule 2)
3. Account Activity Followed by Privilege-Related Activity (Rule 3)
4. Persistence Modification Following Authentication or Privilege Activity (Rule 4)

Strict Forensic Boundaries:
- Purely observational patterns: Detection is NOT proof of compromise, maliciousness, or attacker intent.
- Strictly declarative: Rules contain NO executable code, callbacks, eval(), or exec().
- Non-speculative language: Rejects unsupported conclusions (e.g. 'system compromised', 'confirmed intrusion').
- Deterministic identity: Rule IDs are reproducible RFC 4122 UUIDv5 identifiers.
"""

from typing import Optional, Sequence, Union

from forensix.correlation_models import CorrelationType, RelationshipType
from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    create_rule,
)
from forensix.timeline_models import TimelineCategory

# Standard default time window: 300.0 seconds (5 minutes)
DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS: float = 300.0

# Canonical rule names
RULE_NAME_SSH_AUTH_SUDO: str = "SSH Authentication Followed by Sudo"
RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS: str = "Repeated Failed SSH Attempts Followed by Successful SSH Login"
RULE_NAME_ACCOUNT_PRIVILEGE: str = "Account Activity Followed by Privilege Activity"
RULE_NAME_PERSISTENCE_FOLLOWUP: str = "Persistence Modification Following Authentication or Privilege"


def create_ssh_auth_sudo_rule(
    time_window_seconds: float = DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
) -> DetectionRule:
    """
    Create Rule 1: Successful SSH Login Followed by Sudo.

    Identifies a successful SSH authentication event followed by privileged
    sudo command execution by the same identity within the configured time window.
    """
    return create_rule(
        name=RULE_NAME_SSH_AUTH_SUDO,
        description=(
            "Identifies a successful SSH authentication event followed by privileged "
            "sudo command execution by the same identity within the configured time window."
        ),
        detection_description=(
            "Observed a successful SSH authentication followed by privileged sudo "
            f"execution for the same identity within {int(time_window_seconds)} seconds."
        ),
        required_categories=[TimelineCategory.AUTHENTICATION],
        required_event_types=["ssh_login_success", "sudo_command"],
        required_relationships=[RelationshipType.AUTHENTICATION_PRIVILEGE],
        time_window_seconds=time_window_seconds,
        attributes={
            "rule_type": "initial_v4",
            "pattern_id": "RULE-1-SSH-SUDO",
            "initial_milestone": "V4.5",
        },
    )


def create_repeated_ssh_failure_success_rule(
    time_window_seconds: float = DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
) -> DetectionRule:
    """
    Create Rule 2: Repeated Failed SSH Attempts Followed by Successful SSH Login.

    Identifies failed SSH authentication attempts followed chronologically by
    a successful SSH authentication within the configured time window.
    """
    return create_rule(
        name=RULE_NAME_REPEATED_SSH_FAILURE_SUCCESS,
        description=(
            "Identifies failed SSH authentication attempts followed chronologically "
            "by a successful SSH authentication within the configured time window."
        ),
        detection_description=(
            "Observed failed SSH authentication attempts followed by a successful "
            f"SSH authentication within {int(time_window_seconds)} seconds."
        ),
        required_categories=[TimelineCategory.AUTHENTICATION],
        required_event_types=["ssh_login_failure", "ssh_login_success"],
        time_window_seconds=time_window_seconds,
        attributes={
            "rule_type": "initial_v4",
            "pattern_id": "RULE-2-SSH-FAIL-SUCCESS",
            "initial_milestone": "V4.5",
        },
    )


def create_account_privilege_rule(
    time_window_seconds: float = DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
    account_event_type: str = "user_added",
    privilege_event_type: str = "sudo_command",
) -> DetectionRule:
    """
    Create Rule 3: Account Activity Followed by Privilege-Related Activity.

    Identifies account configuration or creation activity followed by
    privilege-related command execution within the configured time window.
    """
    return create_rule(
        name=RULE_NAME_ACCOUNT_PRIVILEGE,
        description=(
            "Identifies account configuration or creation activity followed by "
            "privilege-related command execution within the configured time window."
        ),
        detection_description=(
            "Observed account activity followed by privilege-related activity "
            f"within {int(time_window_seconds)} seconds."
        ),
        required_categories=[
            TimelineCategory.ACCOUNT,
            TimelineCategory.AUTHENTICATION,
        ],
        required_event_types=[account_event_type, privilege_event_type],
        time_window_seconds=time_window_seconds,
        attributes={
            "rule_type": "initial_v4",
            "pattern_id": "RULE-3-ACCOUNT-PRIVILEGE",
            "initial_milestone": "V4.5",
        },
    )


def create_persistence_followup_rule(
    time_window_seconds: float = DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
    trigger_event_type: str = "sudo_command",
    persistence_event_type: str = "cron_job_scheduled",
) -> DetectionRule:
    """
    Create Rule 4: Persistence Modification Following Authentication or Privilege Activity.

    Identifies authentication or privilege activity followed by persistence
    configuration modification within the configured time window.
    """
    return create_rule(
        name=RULE_NAME_PERSISTENCE_FOLLOWUP,
        description=(
            "Identifies authentication or privilege activity followed by persistence "
            "configuration modification within the configured time window."
        ),
        detection_description=(
            "Observed authentication or privilege activity followed by persistence "
            f"configuration modification within {int(time_window_seconds)} seconds."
        ),
        required_categories=[
            TimelineCategory.AUTHENTICATION,
            TimelineCategory.PERSISTENCE,
        ],
        required_event_types=[trigger_event_type, persistence_event_type],
        time_window_seconds=time_window_seconds,
        attributes={
            "rule_type": "initial_v4",
            "pattern_id": "RULE-4-PERSISTENCE-FOLLOWUP",
            "initial_milestone": "V4.5",
        },
    )


def create_initial_rules(
    time_window_seconds: float = DEFAULT_INITIAL_RULE_TIME_WINDOW_SECONDS,
) -> RuleCollection:
    """
    Create a canonical RuleCollection containing the four initial ForensiX detection rules.

    The collection guarantees deterministic ordering and unique rule identities:
    1. SSH Authentication Followed by Sudo (Rule 1)
    2. Repeated Failed SSH Attempts Followed by Successful SSH Login (Rule 2)
    3. Account Activity Followed by Privilege Activity (Rule 3)
    4. Persistence Modification Following Authentication or Privilege (Rule 4)
    """
    rules = [
        create_ssh_auth_sudo_rule(time_window_seconds=time_window_seconds),
        create_repeated_ssh_failure_success_rule(time_window_seconds=time_window_seconds),
        create_account_privilege_rule(time_window_seconds=time_window_seconds),
        create_persistence_followup_rule(time_window_seconds=time_window_seconds),
    ]
    return RuleCollection(rules)


def get_initial_rules() -> RuleCollection:
    """
    Retrieve the standard initial detection rules as a RuleCollection.
    """
    return create_initial_rules()
