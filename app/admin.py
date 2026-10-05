from django.contrib import admin
from .models import APKScan, MalwareFamily, Quarantine

@admin.register(APKScan)
class APKScanAdmin(admin.ModelAdmin):
    list_display = ("filename", "user", "classification", "risk_score", "status", "scan_date")
    list_filter = ("classification", "status", "scan_date")
    search_fields = ("filename", "package", "sha256")


@admin.register(MalwareFamily)
class MalwareFamilyAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "severity", "signatures", "last_seen")
    list_filter = ("severity", "category")
    search_fields = ("name", "category")


@admin.register(Quarantine)
class QuarantineAdmin(admin.ModelAdmin):
    list_display = ("scan", "quarantined_at")