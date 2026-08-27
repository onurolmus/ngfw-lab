from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import (
    require_http_methods,
    require_POST,
)

from .agent_client import ConfigAgentError, get_firewall_logs
from .forms import FirewallRuleForm
from .models import FirewallRule, PolicyDeployment
from .services import (
    build_policy,
    deploy_current_policy,
    restore_policy_deployment,
)


def admin_required(view_function):
    return user_passes_test(
        lambda user: (
            user.is_authenticated and user.is_superuser
        ),
        login_url="login",
    )(view_function)


@admin_required
def rules_page(request):
    try:
        current_policy = build_policy()
    except ValidationError:
        current_policy = None

    last_applied = PolicyDeployment.objects.filter(
        status=PolicyDeployment.Status.SUCCESS,
        operation__in=[
            PolicyDeployment.Operation.APPLY,
            PolicyDeployment.Operation.RESTORE,
        ],
    ).first()

    has_unapplied_changes = (
        current_policy is not None
        and (
            last_applied is None
            or last_applied.policy != current_policy
        )
    )

    return render(
        request,
        "policies/rules.html",
        {
            "rules": FirewallRule.objects.all(),
            "has_unapplied_changes": has_unapplied_changes,
            "last_applied": last_applied,
        },
    )


@admin_required
@require_http_methods(["GET", "POST"])
def rule_create(request):
    form = FirewallRuleForm(
        request.POST if request.method == "POST" else None
    )

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Kural oluşturuldu.")
        return redirect("rules-page")

    return render(
        request,
        "policies/rule_form.html",
        {"form": form, "title": "Yeni kural"},
    )


@admin_required
@require_http_methods(["GET", "POST"])
def rule_edit(request, rule_pk):
    rule = get_object_or_404(FirewallRule, pk=rule_pk)

    form = FirewallRuleForm(
        request.POST if request.method == "POST" else None,
        instance=rule,
    )

    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Kural güncellendi.")
        return redirect("rules-page")

    return render(
        request,
        "policies/rule_form.html",
        {"form": form, "title": "Kuralı düzenle"},
    )


@admin_required
@require_POST
def rule_delete(request, rule_pk):
    rule = get_object_or_404(FirewallRule, pk=rule_pk)
    rule.delete()

    messages.success(request, "Kural silindi.")
    return redirect("rules-page")


@admin_required
@require_POST
def apply_policy(request):
    try:
        deploy_current_policy(request.user)
        messages.success(request, "Policy başarıyla uygulandı.")
    except ValidationError as error:
        messages.error(request, " ".join(error.messages))
    except ConfigAgentError as error:
        messages.error(request, str(error))

    return redirect("rules-page")


@admin_required
def history_page(request):
    deployments = PolicyDeployment.objects.select_related(
        "requested_by"
    )

    return render(
        request,
        "policies/history.html",
        {"deployments": deployments},
    )


@admin_required
@require_POST
def restore_policy(request, deployment_pk):
    try:
        restore_policy_deployment(
            deployment_pk,
            request.user,
        )
        messages.success(
            request,
            "Geçmiş policy başarıyla geri yüklendi.",
        )
    except (ValidationError, ConfigAgentError) as error:
        messages.error(request, str(error))

    return redirect("history-page")


@admin_required
def logs_page(request):
    firewall_logs = []
    log_error = ""

    try:
        response = get_firewall_logs(100)
        firewall_logs = response.get("logs", [])
    except ConfigAgentError as error:
        log_error = str(error)

    return render(
        request,
        "policies/logs.html",
        {
            "firewall_logs": firewall_logs,
            "log_error": log_error,
        },
    )
