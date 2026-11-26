"""
Canonical Account and SSH Authorized Keys Detection Rules for ForensiX.

Provides declarative, deterministic, and non-speculative DetectionRule definitions
for log-observed account lifecycle changes and SSH authorized_keys activity:
1. New User Account Created (Log)
2. User Account Modified (Log)
3. Account Password Changed (Log)
4. SSH Authorized Keys Referenced or Modified
"""

from forensix.rule_models import (
    ConditionOperator,
    DetectionRule,
    RuleCollection,
    RuleCondition,
    create_rule,
)
from forensix.timeline_models import TimelineCategory

RULE_NAME_USER_ADDED: str = "New User Account Created (Log)"
RULE_NAME_USER_MODIFIED: str = "User Account Modified (Log)"
RULE_NAME_PASSWORD_CHANGED: str = "Account Password Changed (Log)"
RULE_NAME_SSH_KEYS_ACTIVITY: str = "SSH Authorized Keys Referenced or Modified"

SSH_KEY_MODIFIED_EXPLANATION: str = "Observed a log entry indicating SSH authorized_keys was modified."
SSH_KEY_REFERENCED_EXPLANATION: str = "Observed a log entry in which SSH authorized_keys was referenced."


def create_user_added_rule() -> DetectionRule:
    """Create canonical rule detecting user account creation log entries."""
    return create_rule(
        name=RULE_NAME_USER_ADDED,
        description="Identifies syslog entries recording user account creation via useradd or adduser.",
        detection_description="Observed a syslog entry recording user account creation.",
        required_categories=[TimelineCategory.LOG, TimelineCategory.AUTHENTICATION],
        required_event_types=["user_added"],
        severity="high",
        attributes={
            "rule_type": "canonical_account",
            "pattern_id": "ACCT-1-USER-ADDED",
        },
    )


def create_user_modified_rule() -> DetectionRule:
    """Create canonical rule detecting user account modification log entries."""
    return create_rule(
        name=RULE_NAME_USER_MODIFIED,
        description="Identifies syslog entries recording user account configuration or group membership changes via usermod.",
        detection_description="Observed a syslog entry recording a user account modification.",
        required_categories=[TimelineCategory.LOG, TimelineCategory.AUTHENTICATION],
        required_event_types=["user_modified"],
        severity="medium",
        attributes={
            "rule_type": "canonical_account",
            "pattern_id": "ACCT-2-USER-MODIFIED",
        },
    )


def create_password_changed_rule() -> DetectionRule:
    """Create canonical rule detecting account password change log entries."""
    return create_rule(
        name=RULE_NAME_PASSWORD_CHANGED,
        description="Identifies syslog entries recording an account password change via passwd, chpasswd, or PAM chauthtok.",
        detection_description="Observed a syslog entry recording an account password change.",
        required_categories=[TimelineCategory.LOG, TimelineCategory.AUTHENTICATION],
        required_event_types=["password_changed"],
        severity="medium",
        attributes={
            "rule_type": "canonical_account",
            "pattern_id": "ACCT-3-PASSWORD-CHANGED",
        },
    )


def create_ssh_keys_activity_rule() -> DetectionRule:
    """Create canonical rule detecting SSH authorized_keys reference or modification log entries."""
    return create_rule(
        name=RULE_NAME_SSH_KEYS_ACTIVITY,
        description="Identifies syslog or sudo command entries where an SSH authorized_keys file is modified or referenced.",
        detection_description=SSH_KEY_REFERENCED_EXPLANATION,
        required_categories=[TimelineCategory.LOG, TimelineCategory.AUTHENTICATION],
        required_event_types=[],
        conditions=[
            RuleCondition("event_type", ConditionOperator.IN, ["ssh_key_modified", "sudo_command"]),
            RuleCondition("references_authorized_keys", ConditionOperator.EQUALS, True),
        ],
        severity="high",
        attributes={
            "rule_type": "canonical_account",
            "pattern_id": "ACCT-4-SSH-AUTHORIZED-KEYS",
            "key_action_explanations": {
                "modified": SSH_KEY_MODIFIED_EXPLANATION,
                "referenced": SSH_KEY_REFERENCED_EXPLANATION,
            },
        },
    )


def create_canonical_account_rules() -> RuleCollection:
    """Create the canonical RuleCollection containing all 4 account/SSH log rules."""
    return RuleCollection(
        [
            create_user_added_rule(),
            create_user_modified_rule(),
            create_password_changed_rule(),
            create_ssh_keys_activity_rule(),
        ]
    )

