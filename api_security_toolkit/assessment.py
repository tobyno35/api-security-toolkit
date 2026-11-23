"""Validate synthetic inputs and classify authorization observations."""

import re
from collections import Counter

CLASSIFICATIONS = ("confirmed", "suspected", "no_finding", "insufficient_evidence")
CHECK_RELATIONS = {
    "idor_bola": {"same_tenant_other"},
    "broken_function_level_authorization": {"same_tenant_other", "tenant"},
    "cross_tenant_access": {"cross_tenant"},
}
RELATIONS = {"own", "same_tenant_other", "tenant", "cross_tenant"}


class InputError(ValueError):
    """An input does not satisfy the evidence or policy contract."""


def require(condition, message):
    if not condition:
        raise InputError(message)


def fields(value, names, label):
    require(type(value) is dict and value.keys() == set(names.split()),
            f"{label} requires exactly these fields: {names}")


def records(value, label):
    require(type(value) is list, f"{label} must be an array")
    return value


def identifier(value, label):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", value),
            f"{label} must be a nonempty identifier")
    return value


def choice(value, options, label):
    require(type(value) is str and value in options, f"invalid {label}")
    return value


def insert_unique(mapping, key, value, label):
    require(key not in mapping, f"duplicate {label}: {key}")
    mapping[key] = value


def validate_version(document, label):
    require(type(document["schema_version"]) is int and document["schema_version"] == 1,
            f"{label} schema_version must be 1")


def read_policy(document):
    fields(document, "schema_version rules", "policy")
    validate_version(document, "policy")
    rules = {}
    rule_ids = set()
    for rule in records(document["rules"], "rules"):
        fields(rule, "id operation role relation decision", "rule")
        for name in ("id", "operation", "role"):
            identifier(rule[name], f"rule {name}")
        choice(rule["relation"], RELATIONS, "rule relation")
        choice(rule["decision"], {"allow", "deny"}, "rule decision")
        require(rule["id"] not in rule_ids, f"duplicate rule ID: {rule['id']}")
        rule_ids.add(rule["id"])
        key = (rule["operation"], rule["role"], rule["relation"])
        previous = rules.get(key)
        if previous and previous["decision"] != rule["decision"]:
            raise InputError(f"contradictory policy rules: {previous['id']} and {rule['id']}")
        insert_unique(rules, key, rule, "policy key")
    return rules


def actor_relation(actor, resource):
    if actor["tenant"] != resource["tenant"]:
        return "cross_tenant"
    if resource["owner"] is None:
        return "tenant"
    if resource["owner"] == actor["id"]:
        return "own"
    return "same_tenant_other"


def read_evidence(document):
    fields(document, "schema_version synthetic actors resources cases", "evidence")
    validate_version(document, "evidence")
    require(document["synthetic"] is True, "evidence must declare synthetic: true")
    actors, resources, cases = {}, {}, {}
    for actor in records(document["actors"], "actors"):
        fields(actor, "id role tenant", "actor")
        for name in actor:
            identifier(actor[name], f"actor {name}")
        insert_unique(actors, actor["id"], actor, "actor ID")
    for resource in records(document["resources"], "resources"):
        fields(resource, "id tenant owner", "resource")
        for name in ("id", "tenant"):
            identifier(resource[name], f"resource {name}")
        if resource["owner"] is not None:
            owner = identifier(resource["owner"], "resource owner")
            require(owner in actors and actors[owner]["tenant"] == resource["tenant"],
                    f"invalid owner or owner tenant for resource {resource['id']}")
        insert_unique(resources, resource["id"], resource, "resource ID")

    references, decisive_observations = {}, {}
    for case in records(document["cases"], "cases"):
        fields(case, "id check operation resource subject observations", "case")
        for name in ("id", "operation", "resource", "subject"):
            identifier(case[name], f"case {name}")
        choice(case["check"], CHECK_RELATIONS, "case check")
        insert_unique(cases, case["id"], case, "case ID")
        require(case["resource"] in resources and case["subject"] in actors,
                f"unknown resource or subject in case {case['id']}")
        relation = actor_relation(actors[case["subject"]], resources[case["resource"]])
        require(relation in CHECK_RELATIONS[case["check"]],
                f"subject relation {relation} is incompatible with check in case {case['id']}")
        for observation in records(case["observations"], "observations"):
            fields(observation, "ref actor outcome", "observation")
            ref = identifier(observation["ref"], "evidence reference")
            actor = identifier(observation["actor"], "observation actor")
            require(actor in actors, f"unknown actor in observation {ref}")
            outcome = choice(observation["outcome"], {"allowed", "denied", "inconclusive"},
                             "observation outcome")
            key = (case["operation"], case["resource"], actor)
            insert_unique(references, ref, observation, "evidence reference")
            if outcome == "inconclusive":
                continue
            previous = decisive_observations.get(key)
            if previous and previous["outcome"] != outcome:
                raise InputError(f"contradictory observations: {previous['ref']} and {ref}")
            decisive_observations[key] = observation
    return actors, resources, cases


def comparable(check, subject, subject_relation, actor, relation):
    if check == "broken_function_level_authorization":
        return actor["role"] != subject["role"] and relation == subject_relation
    if actor["role"] != subject["role"]:
        return False
    if check == "idor_bola":
        return relation == "own"
    return relation in {"same_tenant_other", "tenant"}


def classify(subject_rule, subject_observations, controls):
    outcomes = {item["outcome"] for item in subject_observations}
    if {"allowed", "denied"} <= outcomes:
        raise InputError("contradictory subject observations")
    if subject_rule is None:
        return "insufficient_evidence", "No explicit permission rule for the subject."
    expected_outcome = {"allow": "allowed", "deny": "denied"}[subject_rule["decision"]]
    if subject_rule["decision"] == "deny" and "allowed" in outcomes:
        if controls:
            return "confirmed", "A denied-by-policy subject succeeded and a comparable permitted control succeeded."
        return "suspected", "A denied-by-policy subject succeeded without a comparable permitted control."
    if expected_outcome in outcomes:
        if expected_outcome == "allowed" or controls:
            return "no_finding", "The observed subject outcome matches explicit policy."
        return "insufficient_evidence", "Subject denial lacks a comparable successful permitted control."
    if "denied" in outcomes:
        return "insufficient_evidence", "An expected permission was denied, so this case cannot verify the check."
    return "insufficient_evidence", "No decisive subject observation."


def assess(evidence, policy):
    rules = read_policy(policy)
    actors, resources, cases = read_evidence(evidence)
    results = []
    for case in sorted(cases.values(), key=lambda item: item["id"]):
        subject = actors[case["subject"]]
        resource = resources[case["resource"]]
        operation = case["operation"]
        subject_relation = actor_relation(subject, resource)
        subject_rule = rules.get((operation, subject["role"], subject_relation))
        observations, subject_observations, controls = [], [], []
        for observation in sorted(case["observations"], key=lambda item: item["ref"]):
            actor = actors[observation["actor"]]
            relation = actor_relation(actor, resource)
            rule = rules.get((operation, actor["role"], relation))
            entry = {
                "ref": observation["ref"], "actor": actor["id"],
                "outcome": observation["outcome"], "role": actor["role"], "tenant": actor["tenant"],
                "relation": relation, "rule_id": rule["id"] if rule else None,
                "expected": rule["decision"] if rule else None,
            }
            observations.append(entry)
            if actor["id"] == subject["id"]:
                subject_observations.append(entry)
            elif (rule and rule["decision"] == "allow" and entry["outcome"] == "allowed"
                  and comparable(case["check"], subject, subject_relation, actor, relation)):
                controls.append(entry["ref"])
        classification, reason = classify(subject_rule, subject_observations, controls)
        results.append({
            "id": case["id"], "check": case["check"], "operation": operation,
            "resource": {name: resource[name] for name in ("id", "tenant", "owner")},
            "subject": {name: subject[name] for name in ("id", "role", "tenant")},
            "subject_relation": subject_relation,
            "subject_rule_id": subject_rule["id"] if subject_rule else None,
            "subject_expected": subject_rule["decision"] if subject_rule else None,
            "classification": classification, "reason": reason,
            "subject_references": [entry["ref"] for entry in subject_observations],
            "control_references": controls, "observations": observations,
        })
    counts = Counter(result["classification"] for result in results)
    return {
        "schema_version": 1, "synthetic": True,
        "summary": {name: counts[name] for name in CLASSIFICATIONS},
        "cases": results,
    }
