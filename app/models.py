from django.db import models
from django.contrib.auth.models import User
import uuid


class MalwareFamily(models.Model):
    """Known Android malware families (threat intel DB)."""
    name = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, default="Medium")
    icon = models.CharField(max_length=50, default="fa-virus")
    description = models.TextField(blank=True)
    attack_vector = models.TextField(blank=True)
    permissions_abused = models.JSONField(default=list, blank=True)
    mitigation = models.TextField(blank=True)
    signatures = models.IntegerField(default=0)
    first_seen = models.CharField(max_length=20, blank=True)
    last_seen = models.CharField(max_length=20, blank=True)
    targets = models.CharField(max_length=200, blank=True)
    tags = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class APKScan(models.Model):
    """A single APK scan record."""
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("analyzing", "Analyzing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    filename = models.CharField(max_length=255)
    package = models.CharField(max_length=255, blank=True, default="")
    file_size = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")
    certificate = models.CharField(max_length=50, blank=True, default="")

    risk_score = models.IntegerField(default=0)
    classification = models.CharField(max_length=20, default="Pending")
    malware_family = models.CharField(max_length=100, blank=True, null=True)
    malware_category = models.CharField(max_length=100, blank=True, null=True)
    ai_confidence = models.IntegerField(default=0)
    family_match = models.IntegerField(default=0)

    detected_risks = models.JSONField(default=list, blank=True)
    capabilities = models.JSONField(default=list, blank=True)
    ai_summary = models.TextField(blank=True, default="")
    recommendation = models.TextField(blank=True, default="")
    breakdown = models.JSONField(default=dict, blank=True)

    status = models.CharField(max_length=20, default="completed", choices=STATUS_CHOICES)
    progress = models.IntegerField(default=100)
    progress_message = models.CharField(max_length=200, blank=True, default="")

    scan_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-scan_date"]

    def __str__(self):
        return f"{self.filename} — {self.classification}"

    @property
    def severity_color(self):
        if self.risk_score >= 70:
            return "red"
        if self.risk_score >= 40:
            return "yellow"
        return "green"


class Quarantine(models.Model):
    """APKs that the user has quarantined."""
    scan = models.OneToOneField(APKScan, on_delete=models.CASCADE)
    quarantined_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)

    class Meta:
        ordering = ["-quarantined_at"]

    def __str__(self):
        return f"Quarantined: {self.scan.filename}"