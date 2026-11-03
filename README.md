# ABR (Agent Blast Radius)

[![CI](https://github.com/CasimirTerr/ABR/actions/workflows/ci.yml/badge.svg)](https://github.com/CasimirTerr/ABR/actions/workflows/ci.yml)

AI agents now get real AWS credentials so they can look up orders, read files, or send messages. If someone hides an instruction in a web page or email the agent reads (prompt injection), the agent can be talked into using those credentials for the attacker.

ABR answers one question before that happens: **if this agent gets hijacked, what can it do in my AWS account that its tools never needed?**

You give it two things:

1. A small manifest listing the agent's tools and which AWS actions each one calls
2. The IAM policy attached to the agent's role

It gives back a blast radius score, findings ranked by severity, and a least-privilege policy you can drop in as a replacement.

No AWS account or credentials needed. It runs offline and has zero dependencies.

**Try it in your browser:** [casimirterr.github.io/ABR](https://casimirterr.github.io/ABR/). Paste an agent's tools and its IAM policy and get the report and blast map right away. Everything runs on the page, so nothing you paste is sent anywhere.

## Quick start

```bash
git clone https://github.com/CasimirTerr/ABR.git
cd ABR
pip install -e .

abr scan -m examples/support-bot/manifest.json -p examples/support-bot/policy.json
```

Output (shortened):

```text
ABR blast radius report: acme-support-bot
============================================================
Blast radius score: 100/100 (Severe)
Findings: 4 critical, 3 high, 4 medium, 3 low
Risky AWS actions the agent can reach: 18 (14 not used by any tool)

[CRITICAL] ABR-001  Lethal trifecta: a prompt injection can steal private data
      - Untrusted input: browse_web, read_support_inbox
      - Private data: read_support_inbox, lookup_order, dynamodb:GetItem, dynamodb:Query, dynamodb:Scan, ...
      - Way out: browse_web, lambda:AddPermission, lambda:CreateFunctionUrlConfig, ses:SendEmail, sqs:SendMessage

[CRITICAL] ABR-108  Privilege escalation path: Lambda with a privileged role
    Can create a Lambda that runs as a more powerful role, then invoke it.
    Fix: Remove iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction from the agent's role.
...
```

The full Markdown report for this example is in [examples/support-bot/report.md](examples/support-bot/report.md).

## Fix it and scan again

```bash
abr scan -m examples/support-bot/manifest.json -p examples/support-bot/policy.json \
  --write-policy least-privilege.json

abr scan -m examples/support-bot/manifest.json -p least-privilege.json
```

With the generated policy, reachable risky actions drop from 18 to 4 and the score drops from 100 to 40. One critical finding is left on purpose: the lethal trifecta. That one is a design problem, not a permissions problem. The bot reads untrusted email, can see customer orders, and can open any URL, so a malicious email can still tell it to put order data in a link. Tighter IAM can't fix that. Splitting the agent or adding human approval can.

## The manifest

```json
{
  "agent": "acme-support-bot",
  "tools": [
    {
      "name": "browse_web",
      "reads_untrusted_input": true,
      "external_comms": true
    },
    {
      "name": "lookup_order",
      "aws_actions": ["dynamodb:GetItem", "dynamodb:Query"],
      "resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
      "touches_private_data": true
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `aws_actions` | Exact AWS actions the tool calls (no wildcards) |
| `resources` | ARNs the tool works on; used to scope the generated policy |
| `reads_untrusted_input` | The tool reads content an outsider can control (web pages, emails, uploaded files, tickets) |
| `external_comms` | The tool can send data outside (HTTP requests, email, webhooks) |
| `touches_private_data` | The tool returns private or customer data |

## What it checks

| ID | Check | Why it matters |
| --- | --- | --- |
| ABR-001 | Lethal trifecta | Untrusted input, private data, and a way out together let a prompt injection steal data |
| ABR-1xx | Privilege escalation paths | 14 known IAM escalation methods, like `iam:PassRole` plus `lambda:CreateFunction` |
| ABR-2xx | Unused risky permissions | About 80 risky actions in 5 groups: data access, exfiltration, privilege escalation, destructive, and turning off logging |
| ABR-301 | Wildcard actions | `*`, `service:*` and `NotAction` grow on their own as AWS adds new actions |
| ABR-302 | Wildcard resources | A tool needs one table but the role allows every table |
| ABR-303 | Unused statements | Leftover statements no tool calls |
| ABR-401 | Missing permissions | A tool will fail because the role doesn't allow what it calls |

If any tool reads untrusted input, unused risky permissions and escalation paths are raised one severity level, because an attacker can steer the agent toward them.

## Use it in CI

```bash
abr scan -m agent.json -p role-policy.json --fail-on high
```

The scan exits with code 1 if any finding is high or critical, so a pull request that gives an agent too much access fails the build. Use `-f md -o report.md` to save a report as a build artifact, or `-f json` to feed other tools.

## Limits

- ABR reads identity policies only. SCPs, permission boundaries and session policies aren't modeled. Those can only take permissions away, so for them ABR may over-report. Resource policies (like S3 bucket or KMS key policies) can also grant access, and ABR doesn't see that.
- Statements with a `Condition` are treated as possibly allowed. A conditional `Deny` doesn't remove an action.
- The manifest is written by hand. If a tool calls an AWS action the manifest doesn't list, ABR can't know about it.

## Credits

- The "lethal trifecta" idea comes from Simon Willison's writing on prompt injection.
- The privilege escalation paths are based on Rhino Security Labs' research on AWS IAM privilege escalation.

## Web playground

The page in [`docs/index.html`](docs/index.html) runs the same checks in JavaScript, with no server. It draws a blast map: risky actions the agent can reach, grouped by type, with the ones no tool uses in the outer ring. A test makes sure its rule catalog matches `abr/catalog.py`. After editing the catalog, run:

```bash
python scripts/sync_web_catalog.py
```

## Run the tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
