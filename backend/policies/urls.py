from django.urls import path

from . import views

urlpatterns = [
    path(
        "rules/",
        views.rule_collection,
        name="rule-collection",
    ),
    path(
        "rules/<int:rule_pk>/",
        views.rule_detail,
        name="rule-detail",
    ),
    path(
        "policy/current/",
        views.current_policy,
        name="current-policy",
    ),
    path(
        "policy/apply/",
        views.apply_current_policy,
        name="apply-policy",
    ),
    path(
        "policy/rollback/",
        views.rollback_policy,
        name="rollback-policy",
    ),
    path(
        "deployments/",
        views.deployment_list,
        name="deployment-list",
    ),
    path(
        "deployments/<int:deployment_pk>/restore/",
        views.restore_policy,
        name="restore-policy",
    ),
    path(
        "logs/",
        views.firewall_logs,
        name="firewall-logs",
    ),
]
