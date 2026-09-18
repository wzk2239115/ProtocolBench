"""Shared helpers for the ProtocolBench live exploit range runner.

Modules
-------
- ``env``  — load host secrets/config from ``.glm_env`` without hardcoding values.
- ``agent`` — build the containerized ``claude_code`` agent execution command.
- ``result`` — normalize per-controller results into the unified schema.
"""
