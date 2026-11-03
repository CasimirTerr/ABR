"""Load the agent manifest: the list of tools an AI agent can call.

Example:

{
  "agent": "support-bot",
  "tools": [
    {"name": "browse_web", "reads_untrusted_input": true, "external_comms": true},
    {"name": "lookup_order", "aws_actions": ["dynamodb:GetItem"],
     "resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
     "touches_private_data": true}
  ]
}
"""

import json
from dataclasses import dataclass, field


@dataclass
class Tool:
    name: str
    description: str = ""
    aws_actions: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    reads_untrusted_input: bool = False
    external_comms: bool = False
    touches_private_data: bool = False


@dataclass
class Manifest:
    agent: str
    tools: list

    @property
    def needed_actions(self):
        seen = []
        for tool in self.tools:
            for action in tool.aws_actions:
                if action.lower() not in [a.lower() for a in seen]:
                    seen.append(action)
        return seen


_TOOL_KEYS = {"name", "description", "aws_actions", "resources",
              "reads_untrusted_input", "external_comms", "touches_private_data"}


def parse_manifest(doc):
    if isinstance(doc, str):
        doc = json.loads(doc)
    if "tools" not in doc or not isinstance(doc["tools"], list):
        raise ValueError("manifest needs a 'tools' list")
    tools = []
    for i, raw in enumerate(doc["tools"]):
        if "name" not in raw:
            raise ValueError(f"tool {i} is missing a 'name'")
        unknown = set(raw) - _TOOL_KEYS
        if unknown:
            raise ValueError(f"tool {raw['name']!r} has unknown keys: {', '.join(sorted(unknown))}")
        for action in raw.get("aws_actions", []):
            if ":" not in action or "*" in action:
                raise ValueError(
                    f"tool {raw['name']!r}: aws_actions must be exact actions like 's3:GetObject', got {action!r}")
        tools.append(Tool(
            name=raw["name"],
            description=raw.get("description", ""),
            aws_actions=list(raw.get("aws_actions", [])),
            resources=list(raw.get("resources", [])),
            reads_untrusted_input=bool(raw.get("reads_untrusted_input", False)),
            external_comms=bool(raw.get("external_comms", False)),
            touches_private_data=bool(raw.get("touches_private_data", False)),
        ))
    return Manifest(agent=doc.get("agent", "unnamed-agent"), tools=tools)


def load_manifest(path):
    with open(path, encoding="utf-8") as fh:
        return parse_manifest(json.load(fh))
