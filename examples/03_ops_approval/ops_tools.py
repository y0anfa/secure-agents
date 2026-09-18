"""Tools for the ops example. The fleet is a dict, so nothing real breaks."""

from secure_agents import tool

FLEET = {
    "i-4a1b2c3d": {"env": "prod", "role": "api"},
    "i-9f8e7d6c": {"env": "prod", "role": "worker"},
    "i-1122aabb": {"env": "staging", "role": "api"},
}


@tool(effects="read", exposure="private")
def list_instances(environment: str) -> str:
    """List instances in an environment.

    Args:
        environment: Either "prod" or "staging".
    """
    rows = [f"{k} {v['role']}" for k, v in FLEET.items() if v["env"] == environment]
    return "\n".join(rows) or "(none)"


@tool(effects="write")
def restart_instance(instance_id: str) -> str:
    """Restart one instance.

    Args:
        instance_id: The instance id, for example "i-4a1b2c3d".
    """
    return f"restarted {instance_id}"


@tool(effects="write")
def terminate_instance(instance_id: str) -> str:
    """Terminate one instance permanently.

    Args:
        instance_id: The instance id, for example "i-4a1b2c3d".
    """
    return f"terminated {instance_id}"
