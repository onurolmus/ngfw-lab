from django import forms

from .models import FirewallRule


class FirewallRuleForm(forms.ModelForm):
    class Meta:
        model = FirewallRule
        fields = (
            "rule_id",
            "enabled",
            "source_zone",
            "destination_zone",
            "source_cidr",
            "destination_cidr",
            "protocol",
            "destination_port",
            "action",
            "log",
            "priority",
        )
