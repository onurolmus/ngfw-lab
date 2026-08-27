from django.db import models
from django.conf import settings

# Create your models here.
import ipaddress

from django.core.exceptions import ValidationError
from django.core.validators import (
    MaxValueValidator,
    MinValueValidator,
    RegexValidator,
)
from django.db import models


rule_id_validator = RegexValidator(
    regex=r"^[a-z0-9][a-z0-9_-]{0,63}$",
    message="Kural kimliği küçük harf, rakam, _ ve - içerebilir.",
)


class FirewallRule(models.Model):
    class Zone(models.TextChoices):
        LAN = "lan", "LAN"
        WAN = "wan", "WAN"

    class Protocol(models.TextChoices):
        ANY = "any", "Any"
        ICMP = "icmp", "ICMP"
        TCP = "tcp", "TCP"
        UDP = "udp", "UDP"

    class Action(models.TextChoices):
        ACCEPT = "accept", "İzin ver"
        DROP = "drop", "Engelle"

    rule_id = models.CharField(
        max_length=64,
        unique=True,
        validators=[rule_id_validator],
    )
    enabled = models.BooleanField(default=True)

    source_zone = models.CharField(max_length=8, choices=Zone.choices)
    destination_zone = models.CharField(max_length=8, choices=Zone.choices)

    source_cidr = models.CharField(max_length=18)
    destination_cidr = models.CharField(max_length=18)

    protocol = models.CharField(
        max_length=8,
        choices=Protocol.choices,
        default=Protocol.ANY,
    )
    destination_port = models.PositiveIntegerField(
        null=True,
        blank=True,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(65535),
        ],
    )

    action = models.CharField(
        max_length=8,
        choices=Action.choices,
        default=Action.ACCEPT,
    )
    log = models.BooleanField(default=False)
    priority = models.PositiveIntegerField(
        default=100,
        validators=[MinValueValidator(1)],
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority", "id"]

    def clean(self):
        super().clean()
        errors = {}

        if self.source_zone == self.destination_zone:
            errors["destination_zone"] = (
                "Kaynak ve hedef zone aynı olamaz."
            )

        for field_name in ("source_cidr", "destination_cidr"):
            value = getattr(self, field_name)

            try:
                network = ipaddress.ip_network(value, strict=True)

                if network.version != 4:
                    raise ValueError
            except ValueError:
                errors[field_name] = (
                    "Geçerli bir IPv4 ağ CIDR adresi girilmelidir."
                )

        if self.protocol in {self.Protocol.TCP, self.Protocol.UDP}:
            if self.destination_port is None:
                errors["destination_port"] = (
                    "TCP ve UDP kuralları için hedef port gereklidir."
                )
        elif self.destination_port is not None:
            errors["destination_port"] = (
                "Yalnızca TCP ve UDP kuralları port kullanabilir."
            )

        if errors:
            raise ValidationError(errors)

    def __str__(self):
        return self.rule_id

class PolicyDeployment(models.Model):
    class Operation(models.TextChoices):
        APPLY = "apply", "Uygulama"
        ROLLBACK = "rollback", "Son işlemi geri alma"
        RESTORE = "restore", "Geçmiş sürüme dönme"

    class Status(models.TextChoices):
        PENDING = "pending", "Bekliyor"
        SUCCESS = "success", "Başarılı"
        FAILED = "failed", "Başarısız"

    operation = models.CharField(
        max_length=16,
        choices=Operation.choices,
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )

    policy = models.JSONField(default=dict, blank=True)
    agent_response = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.operation} - {self.status}"
