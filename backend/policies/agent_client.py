import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings


class ConfigAgentError(Exception):
    pass


def request_agent(method, path, payload=None):
    if not settings.NGFW_AGENT_TOKEN:
        raise ConfigAgentError("Config-agent token tanımlanmamış.")

    headers = {
        "Authorization": (
            f"Bearer {settings.NGFW_AGENT_TOKEN}"
        ),
        "Accept": "application/json",
    }

    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = Request(
        url=f"{settings.NGFW_AGENT_URL}{path}",
        data=data,
        method=method,
        headers=headers,
    )

    try:
        with urlopen(request, timeout=10) as response:
            response_body = response.read().decode("utf-8")
    except HTTPError as error:
        error_body = error.read().decode(
            "utf-8",
            errors="replace",
        )
        raise ConfigAgentError(
            f"Config-agent HTTP {error.code}: {error_body}"
        ) from error
    except URLError as error:
        raise ConfigAgentError(
            f"Config-agent bağlantı hatası: {error.reason}"
        ) from error

    try:
        return json.loads(response_body)
    except json.JSONDecodeError as error:
        raise ConfigAgentError(
            "Config-agent geçersiz JSON yanıtı döndürdü."
        ) from error


def apply_policy(policy):
    return request_agent("POST", "/v1/policy", policy)


def rollback_policy():
    return request_agent("POST", "/v1/rollback")


def get_firewall_logs(limit=100):
    query = urlencode({"limit": limit})

    return request_agent(
        "GET",
        f"/v1/logs?{query}",
    )
