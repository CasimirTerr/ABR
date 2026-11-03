"""Work out the blast radius of a hijacked AI agent.

The question ABR asks: if someone hijacks this agent through prompt injection,
what can they make it do in AWS that its tools never needed?
"""

import re
from dataclasses import dataclass, field

from . import catalog
from .iam import evaluate, is_wildcard_resource

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1}

# Base severity for permissions an agent has but none of its tools use.
_CATEGORY_SEVERITY = {
    catalog.PRIVILEGE_ESCALATION: "HIGH",
    catalog.DEFENSE_EVASION: "HIGH",
    catalog.DESTRUCTIVE: "MEDIUM",
    catalog.EXFILTRATION: "MEDIUM",
    catalog.DATA_ACCESS: "MEDIUM",
}


def _bump(severity):
    """One level more severe. Used when the agent reads attacker-controlled input."""
    i = SEVERITIES.index(severity)
    return SEVERITIES[max(0, i - 1)]


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    fix: str
    actions: list = field(default_factory=list)
    tools: list = field(default_factory=list)


@dataclass
class Result:
    agent: str
    findings: list
    reachable: dict          # risky action -> Decision
    needed: list             # actions the tools actually call
    score: int
    least_privilege_policy: dict

    def count(self, severity):
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def excess_risky(self):
        needed = {a.lower() for a in self.needed}
        return sorted(a for a in self.reachable if a.lower() not in needed)

    def worst_at_or_above(self, threshold):
        if threshold == "none":
            return False
        limit = SEVERITIES.index(threshold.upper())
        return any(SEVERITIES.index(f.severity) <= limit for f in self.findings)


def analyze(manifest, statements):
    findings = []
    needed = manifest.needed_actions
    needed_lower = {a.lower() for a in needed}
    untrusted_tools = [t.name for t in manifest.tools if t.reads_untrusted_input]
    hijackable = bool(untrusted_tools)

    # 1. Which risky actions can the agent's role actually perform?
    reachable = {}
    for action in catalog.RISKY_ACTIONS:
        decision = evaluate(statements, action)
        if decision.allowed:
            reachable[action] = decision
    excess = {a: d for a, d in reachable.items() if a.lower() not in needed_lower}

    # 2. The "lethal trifecta": untrusted input + private data + a way out.
    private_tools = [t.name for t in manifest.tools if t.touches_private_data]
    private_actions = sorted(a for a in reachable if catalog.DATA_ACCESS in catalog.RISKY_ACTIONS[a])
    exfil_tools = [t.name for t in manifest.tools if t.external_comms]
    exfil_actions = sorted(a for a in reachable if catalog.EXFILTRATION in catalog.RISKY_ACTIONS[a])
    if untrusted_tools and (private_tools or private_actions) and (exfil_tools or exfil_actions):
        legs = [
            f"Untrusted input: {', '.join(untrusted_tools)}",
            "Private data: " + ", ".join(private_tools + private_actions[:6]
                                         + (["..."] if len(private_actions) > 6 else [])),
            "Way out: " + ", ".join(exfil_tools + exfil_actions[:6]
                                    + (["..."] if len(exfil_actions) > 6 else [])),
        ]
        findings.append(Finding(
            id="ABR-001",
            severity="CRITICAL",
            title="Lethal trifecta: a prompt injection can steal private data",
            detail=("The agent reads attacker-controlled content, can reach private data, and has a "
                    "way to send data out. A hidden instruction in a web page or email could make it "
                    "read secrets and send them to the attacker.\n" + "\n".join(f"  - {leg}" for leg in legs)),
            fix=("Break one leg: run the untrusted-input tool in a separate agent with no data access, "
                 "remove the outbound tool, or require human approval before anything is sent out."),
            actions=private_actions + exfil_actions,
            tools=untrusted_tools + private_tools + exfil_tools,
        ))

    # 3. Known privilege escalation paths.
    reachable_lower = {a.lower() for a in reachable}
    for n, (name, required, why) in enumerate(catalog.ESCALATION_PATHS, start=1):
        if all(r.lower() in reachable_lower for r in required):
            if all(r.lower() in needed_lower for r in required):
                continue  # a tool really needs this; still reported via broad-resource checks
            findings.append(Finding(
                id=f"ABR-1{n:02d}",
                severity="CRITICAL" if hijackable else "HIGH",
                title=f"Privilege escalation path: {name}",
                detail=why + (" The agent reads untrusted input, so an attacker can steer it here."
                              if hijackable else ""),
                fix=f"Remove {', '.join(required)} from the agent's role.",
                actions=list(required),
            ))

    # 4. Risky permissions no tool needs, grouped by category.
    by_category = {}
    for action in excess:
        for cat in catalog.RISKY_ACTIONS[action]:
            by_category.setdefault(cat, []).append(action)
    for i, cat in enumerate(_CATEGORY_SEVERITY, start=1):
        actions = sorted(by_category.get(cat, []))
        if not actions:
            continue
        severity = _CATEGORY_SEVERITY[cat]
        if hijackable:
            severity = _bump(severity)
        findings.append(Finding(
            id=f"ABR-2{i:02d}",
            severity=severity,
            title=f"Unused permissions: {catalog.CATEGORY_LABELS[cat].lower()}",
            detail=(f"{len(actions)} risky action(s) in this category are allowed but no tool uses them. "
                    "They only add to what a hijacked agent could do."),
            fix="Remove these actions from the role, or replace the policy with the generated least-privilege policy.",
            actions=actions,
        ))

    # 5. Overly broad statements (Action "*" or "service:*").
    for st in statements:
        if st.effect != "Allow":
            continue
        broad = [a for a in st.actions if a == "*" or a.endswith(":*")]
        if st.not_actions:
            broad.append("NotAction (allows everything not listed)")
        if broad:
            findings.append(Finding(
                id="ABR-301",
                severity="HIGH" if "*" in broad or st.not_actions else "MEDIUM",
                title=f"Wildcard permission in statement '{st.sid}'",
                detail=f"Allows {', '.join(broad)}. New AWS actions get added to wildcards automatically.",
                fix="List the exact actions the tools call instead of a wildcard.",
                actions=broad,
            ))

    # 6. Tools that name specific resources but the role allows every resource.
    for tool in manifest.tools:
        if not tool.aws_actions or not tool.resources:
            continue
        wide = [a for a in tool.aws_actions if evaluate(statements, a).wildcard_resource]
        if wide:
            findings.append(Finding(
                id="ABR-302",
                severity="MEDIUM",
                title=f"Tool '{tool.name}' only needs specific resources but the role allows all of them",
                detail=(f"{', '.join(wide)} {'is' if len(wide) == 1 else 'are'} allowed on every resource, "
                        "but the tool only uses "
                        f"{', '.join(tool.resources)}."),
                fix="Scope the Resource element to the ARNs listed for this tool.",
                actions=wide,
                tools=[tool.name],
            ))

    # 7. Allow statements no tool uses at all.
    for st in statements:
        if st.effect != "Allow" or not st.actions:
            continue
        if any(st.covers(a) for a in needed):
            continue
        findings.append(Finding(
            id="ABR-303",
            severity="LOW",
            title=f"Statement '{st.sid}' is not used by any tool",
            detail=f"It allows {', '.join(st.actions)}, but no tool in the manifest calls these.",
            fix="Delete the statement.",
            actions=list(st.actions),
        ))

    # 8. Tools that will fail because the role does not allow what they call.
    for tool in manifest.tools:
        missing = [a for a in tool.aws_actions if not evaluate(statements, a).allowed]
        if missing:
            findings.append(Finding(
                id="ABR-401",
                severity="LOW",
                title=f"Tool '{tool.name}' is missing permissions",
                detail=f"The role does not allow {', '.join(missing)}, so this tool will fail.",
                fix="Add these actions (scoped to the tool's resources) or remove the tool.",
                actions=missing,
                tools=[tool.name],
            ))

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.id))
    score = min(100, sum(SEVERITY_POINTS[f.severity] for f in findings))
    return Result(
        agent=manifest.agent,
        findings=findings,
        reachable=reachable,
        needed=needed,
        score=score,
        least_privilege_policy=least_privilege_policy(manifest),
    )


def _sid(name):
    cleaned = re.sub(r"[^A-Za-z0-9]", " ", name).title().replace(" ", "")
    return cleaned or "Tool"


def least_privilege_policy(manifest):
    """Build an IAM policy that allows exactly what the tools call, and nothing else."""
    statements = []
    for tool in manifest.tools:
        if not tool.aws_actions:
            continue
        statements.append({
            "Sid": _sid(tool.name),
            "Effect": "Allow",
            "Action": sorted(set(tool.aws_actions)),
            "Resource": tool.resources or "*",
        })
    return {"Version": "2012-10-17", "Statement": statements}


def tools_without_resources(manifest):
    """Tools whose generated statement would still allow every resource."""
    return [t.name for t in manifest.tools
            if t.aws_actions and (not t.resources or any(is_wildcard_resource(r) for r in t.resources))]
