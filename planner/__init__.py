"""Deterministic firewall change planner.

Takes a normalized request (src, dst, service, target firewalls) and computes
the full change plan — zone verdict, existing-rule coverage, object
reuse/create, rule insertion point, and FortiGate CLI — entirely in tested
code. No LLM involvement: the conversational layer only collects inputs and
presents this module's output.
"""
