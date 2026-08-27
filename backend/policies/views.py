import json
from functools import wraps

from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.http import (
    require_GET,
    require_POST,
    require_http_methods,
)

from .agent_client import ConfigAgentError, get_firewall_logs
from .forms import FirewallRuleForm
from .models import FirewallRule, PolicyDeployment
from .services import (
    build_policy,
    deploy_current_policy,
    deploy_rollback,
    restore_policy_deployment,
)


def staff_api_required(view_function):
    @wraps(view_function)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse(
                {"status": "error", "error": "Giriş gerekli."},
                status=401,
            )

        if not request.user.is_staff:
            return JsonResponse(
                {"status": "error", "error": "Yetki yetersiz."},
                status=403,
            )

        return view_function(request, *args, **kwargs)

    return wrapped


def validation_errors(error):
    if hasattr(error, "message_dict"):
        return error.message_dict

    return {"policy": error.messages}


def parse_json_body(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValidationError(
            {"body": "Geçerli bir JSON nesnesi gönderilmelidir."}
        )

    if not isinstance(data, dict):
        raise ValidationError(
            {"body": "JSON gövdesi bir nesne olmalıdır."}
        )

    return data


def rule_to_dict(rule):
    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "enabled": rule.enabled,
        "source_zone": rule.source_zone,
        "destination_zone": rule.destination_zone,
        "source_cidr": rule.source_cidr,
        "destination_cidr": rule.destination_cidr,
        "protocol": rule.protocol,
        "destination_port": rule.destination_port,
        "action": rule.action,
        "log": rule.log,
        "priority": rule.priority,
    }


@staff_api_required
@require_http_methods(["GET", "POST"])
def rule_collection(request):
    if request.method == "GET":
        rules = [
            rule_to_dict(rule)
            for rule in FirewallRule.objects.all()
        ]

        return JsonResponse(
            {"status": "ok", "rules": rules}
        )

    try:
        data = parse_json_body(request)
    except ValidationError as error:
        return JsonResponse(
            {
                "status": "error",
                "errors": validation_errors(error),
            },
            status=400,
        )

    form = FirewallRuleForm(data=data)

    if not form.is_valid():
        return JsonResponse(
            {
                "status": "error",
                "errors": form.errors.get_json_data(),
            },
            status=400,
        )

    rule = form.save()

    return JsonResponse(
        {"status": "ok", "rule": rule_to_dict(rule)},
        status=201,
    )


@staff_api_required
@require_http_methods(["GET", "PUT", "DELETE"])
def rule_detail(request, rule_pk):
    try:
        rule = FirewallRule.objects.get(pk=rule_pk)
    except FirewallRule.DoesNotExist:
        return JsonResponse(
            {"status": "error", "error": "Kural bulunamadı."},
            status=404,
        )

    if request.method == "GET":
        return JsonResponse(
            {"status": "ok", "rule": rule_to_dict(rule)}
        )

    if request.method == "DELETE":
        deleted_rule_id = rule.rule_id
        rule.delete()

        return JsonResponse(
            {
                "status": "ok",
                "message": "Kural silindi.",
                "rule_id": deleted_rule_id,
            }
        )

    try:
        data = parse_json_body(request)
    except ValidationError as error:
        return JsonResponse(
            {
                "status": "error",
                "errors": validation_errors(error),
            },
            status=400,
        )

    form = FirewallRuleForm(data=data, instance=rule)

    if not form.is_valid():
        return JsonResponse(
            {
                "status": "error",
                "errors": form.errors.get_json_data(),
            },
            status=400,
        )

    rule = form.save()

    return JsonResponse(
        {"status": "ok", "rule": rule_to_dict(rule)}
    )


@staff_api_required
@require_GET
def current_policy(request):
    try:
        policy = build_policy()
    except ValidationError as error:
        return JsonResponse(
            {
                "status": "error",
                "errors": validation_errors(error),
            },
            status=400,
        )

    return JsonResponse({"status": "ok", "policy": policy})


@staff_api_required
@require_POST
def apply_current_policy(request):
    try:
        deployment = deploy_current_policy(request.user)
    except ValidationError as error:
        return JsonResponse(
            {
                "status": "error",
                "errors": validation_errors(error),
            },
            status=400,
        )
    except ConfigAgentError as error:
        return JsonResponse(
            {"status": "error", "error": str(error)},
            status=502,
        )

    return JsonResponse(
        {
            "status": "ok",
            "deployment_id": deployment.id,
            "agent_response": deployment.agent_response,
        }
    )


@staff_api_required
@require_POST
def rollback_policy(request):
    try:
        deployment = deploy_rollback(request.user)
    except ConfigAgentError as error:
        return JsonResponse(
            {"status": "error", "error": str(error)},
            status=502,
        )

    return JsonResponse(
        {
            "status": "ok",
            "deployment_id": deployment.id,
            "agent_response": deployment.agent_response,
        }
    )


@staff_api_required
@require_GET
def deployment_list(request):
    deployments = []

    queryset = PolicyDeployment.objects.select_related(
        "requested_by"
    )[:100]

    for deployment in queryset:
        deployments.append(
            {
                "id": deployment.id,
                "operation": deployment.operation,
                "status": deployment.status,
                "policy": deployment.policy,
                "agent_response": deployment.agent_response,
                "error": deployment.error,
                "requested_by": (
                    deployment.requested_by.username
                    if deployment.requested_by
                    else None
                ),
                "created_at": deployment.created_at,
                "finished_at": deployment.finished_at,
            }
        )

    return JsonResponse(
        {"status": "ok", "deployments": deployments}
    )
@staff_api_required
@require_POST
def restore_policy(request, deployment_pk):
    try:
        deployment = restore_policy_deployment(
            deployment_pk,
            request.user,
        )
    except ValidationError as error:
        return JsonResponse(
            {
                "status": "error",
                "errors": validation_errors(error),
            },
            status=400,
        )
    except ConfigAgentError as error:
        return JsonResponse(
            {"status": "error", "error": str(error)},
            status=502,
        )

    return JsonResponse(
        {
            "status": "ok",
            "deployment_id": deployment.id,
            "agent_response": deployment.agent_response,
        }
    )
@staff_api_required
@require_GET
def firewall_logs(request):
    raw_limit = request.GET.get("limit", "100")

    try:
        limit = int(raw_limit)
    except ValueError:
        return JsonResponse(
            {
                "status": "error",
                "error": "limit sayı olmalıdır.",
            },
            status=400,
        )

    if limit < 1 or limit > 500:
        return JsonResponse(
            {
                "status": "error",
                "error": "limit 1 ile 500 arasında olmalıdır.",
            },
            status=400,
        )

    try:
        response = get_firewall_logs(limit)
    except ConfigAgentError as error:
        return JsonResponse(
            {"status": "error", "error": str(error)},
            status=502,
        )

    return JsonResponse(response)
