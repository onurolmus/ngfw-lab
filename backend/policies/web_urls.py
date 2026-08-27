from django.urls import path

from . import web_views


urlpatterns = [
    path("", web_views.rules_page, name="rules-page"),
    path(
        "rules/new/",
        web_views.rule_create,
        name="rule-create",
    ),
    path(
        "rules/<int:rule_pk>/edit/",
        web_views.rule_edit,
        name="rule-edit",
    ),
    path(
        "rules/<int:rule_pk>/delete/",
        web_views.rule_delete,
        name="rule-delete",
    ),
    path(
        "policy/apply/",
        web_views.apply_policy,
        name="web-apply-policy",
    ),
    path(
        "history/",
        web_views.history_page,
        name="history-page",
    ),
    path(
        "history/<int:deployment_pk>/restore/",
        web_views.restore_policy,
        name="web-restore-policy",
    ),
    path("logs/", web_views.logs_page, name="logs-page"),
]
