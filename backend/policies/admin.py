from django.contrib import admin

# Register your models here.
from django.contrib import admin

from .models import FirewallRule, PolicyDeployment


@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = (
        "rule_id",
        "enabled",
        "source_zone",
        "destination_zone",
        "protocol",
        "destination_port",
        "action",
        "priority",
        "updated_at",
    )
    list_filter = (
        "enabled",
        "source_zone",
        "destination_zone",
        "protocol",
        "action",
    )
    search_fields = (
        "rule_id",
        "source_cidr",
        "destination_cidr",
    )
    ordering = ("priority", "id")


@admin.register(PolicyDeployment)
class PolicyDeploymentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "operation",
        "status",
        "requested_by",
        "created_at",
        "finished_at",
    )
    list_filter = ("operation", "status")
    readonly_fields = (
        "operation",
        "status",
        "policy",
        "agent_response",
        "error",
        "requested_by",
        "created_at",
        "finished_at",
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
