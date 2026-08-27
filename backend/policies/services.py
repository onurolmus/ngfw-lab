from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction

from .agent_client import (
    ConfigAgentError,
    apply_policy,
    rollback_policy,
)
from .models import FirewallRule, PolicyDeployment


def serialize_rule(rule):
    rule.full_clean()

    data = {
        "id": rule.rule_id,
        "enabled": rule.enabled,
        "source_zone": rule.source_zone,
        "destination_zone": rule.destination_zone,
        "source_cidr": rule.source_cidr,
        "destination_cidr": rule.destination_cidr,
        "protocol": rule.protocol,
        "action": rule.action,
        "log": rule.log,
    }

    if rule.destination_port is not None:
        data["destination_port"] = rule.destination_port

    return data


def build_policy():
    rules = list(
        FirewallRule.objects.order_by("priority", "id")
    )

    if not rules:
        raise ValidationError(
            "Uygulanacak en az bir kural olmalıdır."
        )

    return {
        "version": 1,
        "rules": [serialize_rule(rule) for rule in rules],
    }


def get_requested_by(user):
    if user is not None and user.is_authenticated:
        return user

    return None


def deploy_current_policy(requested_by=None):
    policy = build_policy()

    deployment = PolicyDeployment.objects.create(
        operation=PolicyDeployment.Operation.APPLY,
        status=PolicyDeployment.Status.PENDING,
        policy=policy,
        requested_by=get_requested_by(requested_by),
    )

    try:
        response = apply_policy(policy)
    except ConfigAgentError as error:
        deployment.status = PolicyDeployment.Status.FAILED
        deployment.error = str(error)
        deployment.finished_at = timezone.now()
        deployment.save(
            update_fields=[
                "status",
                "error",
                "finished_at",
            ]
        )
        raise

    deployment.status = PolicyDeployment.Status.SUCCESS
    deployment.agent_response = response
    deployment.finished_at = timezone.now()
    deployment.save(
        update_fields=[
            "status",
            "agent_response",
            "finished_at",
        ]
    )

    return deployment


def deploy_rollback(requested_by=None):
    deployment = PolicyDeployment.objects.create(
        operation=PolicyDeployment.Operation.ROLLBACK,
        status=PolicyDeployment.Status.PENDING,
        requested_by=get_requested_by(requested_by),
    )

    try:
        response = rollback_policy()
    except ConfigAgentError as error:
        deployment.status = PolicyDeployment.Status.FAILED
        deployment.error = str(error)
        deployment.finished_at = timezone.now()
        deployment.save(
            update_fields=[
                "status",
                "error",
                "finished_at",
            ]
        )
        raise

    deployment.status = PolicyDeployment.Status.SUCCESS
    deployment.agent_response = response
    deployment.finished_at = timezone.now()
    deployment.save(
        update_fields=[
            "status",
            "agent_response",
            "finished_at",
        ]
    )

    return deployment
def restore_policy_deployment(
    deployment_id,
    requested_by=None,
):
    try:
        target = PolicyDeployment.objects.get(
            pk=deployment_id,
            status=PolicyDeployment.Status.SUCCESS,
        )
    except PolicyDeployment.DoesNotExist:
        raise ValidationError(
            {"deployment": "Başarılı geçmiş kaydı bulunamadı."}
        )

    policy = target.policy

    if (
        not isinstance(policy, dict)
        or policy.get("version") != 1
        or not isinstance(policy.get("rules"), list)
        or not policy["rules"]
    ):
        raise ValidationError(
            {"deployment": "Geçmiş policy verisi geçersiz."}
        )

    restored_rules = []
    seen_rule_ids = set()

    for position, rule_data in enumerate(policy["rules"], start=1):
        try:
            rule = FirewallRule(
                rule_id=rule_data["id"],
                enabled=rule_data["enabled"],
                source_zone=rule_data["source_zone"],
                destination_zone=rule_data["destination_zone"],
                source_cidr=rule_data["source_cidr"],
                destination_cidr=rule_data["destination_cidr"],
                protocol=rule_data["protocol"],
                destination_port=rule_data.get(
                    "destination_port"
                ),
                action=rule_data["action"],
                log=rule_data["log"],
                priority=position * 100,
            )
        except (KeyError, TypeError):
            raise ValidationError(
                {"deployment": "Geçmişteki kural eksik alan içeriyor."}
            )

        if rule.rule_id in seen_rule_ids:
            raise ValidationError(
                {"deployment": "Geçmişte tekrar eden kural kimliği var."}
            )

        seen_rule_ids.add(rule.rule_id)
        rule.full_clean(validate_unique=False)
        restored_rules.append(rule)

    deployment = PolicyDeployment.objects.create(
        operation=PolicyDeployment.Operation.RESTORE,
        status=PolicyDeployment.Status.PENDING,
        policy=policy,
        requested_by=get_requested_by(requested_by),
    )

    try:
        response = apply_policy(policy)
    except ConfigAgentError as error:
        deployment.status = PolicyDeployment.Status.FAILED
        deployment.error = str(error)
        deployment.finished_at = timezone.now()
        deployment.save(
            update_fields=["status", "error", "finished_at"]
        )
        raise

    try:
        with transaction.atomic():
            FirewallRule.objects.all().delete()
            FirewallRule.objects.bulk_create(restored_rules)
    except Exception as error:
        try:
            rollback_policy()
            rollback_error = ""
        except ConfigAgentError as secondary_error:
            rollback_error = f" Rollback hatası: {secondary_error}"

        deployment.status = PolicyDeployment.Status.FAILED
        deployment.error = (
            f"Veritabanı geri yüklenemedi: {error}.{rollback_error}"
        )
        deployment.finished_at = timezone.now()
        deployment.save(
            update_fields=["status", "error", "finished_at"]
        )

        raise ValidationError(
            {"deployment": deployment.error}
        )

    deployment.status = PolicyDeployment.Status.SUCCESS
    deployment.agent_response = response
    deployment.finished_at = timezone.now()
    deployment.save(
        update_fields=[
            "status",
            "agent_response",
            "finished_at",
        ]
    )

    return deployment
