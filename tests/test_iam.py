import pytest

from abr.iam import action_matches, evaluate, is_wildcard_resource, parse_policy


def policy(*statements):
    return parse_policy({"Version": "2012-10-17", "Statement": list(statements)})


@pytest.mark.parametrize("pattern,action,expected", [
    ("s3:GetObject", "s3:GetObject", True),
    ("s3:getobject", "s3:GetObject", True),   # IAM actions are case-insensitive
    ("s3:Get*", "s3:GetObject", True),
    ("s3:Get*", "s3:PutObject", False),
    ("*", "iam:PassRole", True),
    ("iam:*Policy", "iam:PutRolePolicy", True),
    ("ec2:?unInstances", "ec2:RunInstances", True),
    ("s3:Get", "s3:GetObject", False),
])
def test_action_matches(pattern, action, expected):
    assert action_matches(pattern, action) is expected


def test_allow_and_unrelated_action():
    st = policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    assert evaluate(st, "s3:GetObject").allowed
    assert not evaluate(st, "s3:PutObject").allowed


def test_explicit_deny_wins():
    st = policy(
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"},
    )
    assert evaluate(st, "s3:GetObject").allowed
    assert not evaluate(st, "s3:DeleteBucket").allowed


def test_conditional_deny_is_treated_as_still_reachable():
    st = policy(
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
    )
    decision = evaluate(st, "s3:DeleteBucket")
    assert decision.allowed and decision.conditional


def test_not_action_allows_everything_else():
    st = policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert evaluate(st, "s3:GetObject").allowed
    assert not evaluate(st, "iam:PassRole").allowed


def test_scoped_resource_is_not_wildcard():
    st = policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::kb/*"})
    decision = evaluate(st, "s3:GetObject")
    assert decision.allowed and not decision.wildcard_resource


@pytest.mark.parametrize("resource,expected", [
    ("*", True),
    ("arn:aws:s3:::*", True),
    ("arn:aws:dynamodb:us-east-1:111122223333:*", True),
    ("arn:aws:s3:::kb/*", False),
    ("arn:aws:dynamodb:us-east-1:111122223333:table/orders", False),
])
def test_is_wildcard_resource(resource, expected):
    assert is_wildcard_resource(resource) is expected


def test_single_statement_object_and_bad_effect():
    assert len(parse_policy({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}})) == 1
    with pytest.raises(ValueError):
        parse_policy({"Statement": [{"Effect": "Maybe", "Action": "s3:*"}]})
