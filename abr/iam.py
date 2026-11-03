"""Small, dependency-free IAM policy evaluator.

It answers one question: "is this action allowed by these identity policies?"
It handles Allow/Deny, Action/NotAction, wildcards (* and ?), Resource scoping
and Conditions. It does not model SCPs, permission boundaries or resource
policies, and it says so in the report.
"""

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass
class Statement:
    effect: str
    actions: list = field(default_factory=list)
    not_actions: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    has_condition: bool = False
    sid: str = ""
    source: str = ""

    def covers(self, action):
        if self.actions:
            return any(action_matches(p, action) for p in self.actions)
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return False


@dataclass
class Decision:
    allowed: bool
    conditional: bool = False
    wildcard_resource: bool = False
    resources: list = field(default_factory=list)
    statements: list = field(default_factory=list)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


@lru_cache(maxsize=4096)
def _pattern_to_regex(pattern):
    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile("^" + escaped + "$", re.IGNORECASE)


def action_matches(pattern, action):
    """True if an IAM action pattern like 's3:Get*' matches 's3:GetObject'."""
    return bool(_pattern_to_regex(pattern).match(action))


_BROAD_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[^:]*:[^:]*:\*$", re.IGNORECASE)


def is_wildcard_resource(resource):
    """True for '*' or an ARN that covers every resource of a service, like 'arn:aws:s3:::*'."""
    return resource == "*" or bool(_BROAD_ARN.match(resource))


def parse_policy(doc, source=""):
    """Turn a policy document (dict or JSON string) into Statements."""
    if isinstance(doc, str):
        doc = json.loads(doc)
    raw = doc.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    statements = []
    for i, st in enumerate(raw):
        effect = st.get("Effect", "")
        if effect not in ("Allow", "Deny"):
            raise ValueError(f"{source or 'policy'}: statement {i} has invalid Effect {effect!r}")
        resources = _as_list(st.get("Resource"))
        if st.get("NotResource") is not None:
            # NotResource means "everything except", so treat it as broad.
            resources = ["*"]
        statements.append(Statement(
            effect=effect,
            actions=_as_list(st.get("Action")),
            not_actions=_as_list(st.get("NotAction")),
            resources=resources or ["*"],
            has_condition=bool(st.get("Condition")),
            sid=st.get("Sid", f"Statement{i}"),
            source=source,
        ))
    return statements


def evaluate(statements, action):
    """Decide whether `action` is allowed.

    An unconditional explicit Deny wins. A Deny with a Condition might not
    apply at runtime, so we stay cautious and still treat the action as
    reachable (marked conditional).
    """
    allows = [s for s in statements if s.effect == "Allow" and s.covers(action)]
    denies = [s for s in statements if s.effect == "Deny" and s.covers(action)]

    if any(not d.has_condition for d in denies):
        return Decision(allowed=False, statements=denies)
    if not allows:
        return Decision(allowed=False)

    unconditional = [a for a in allows if not a.has_condition]
    conditional = not unconditional or bool(denies)
    resources = sorted({r for a in allows for r in a.resources})
    return Decision(
        allowed=True,
        conditional=conditional,
        wildcard_resource=any(is_wildcard_resource(r) for r in resources),
        resources=resources,
        statements=allows,
    )


def load_policies(paths):
    statements = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            statements.extend(parse_policy(json.load(fh), source=str(path)))
    return statements
