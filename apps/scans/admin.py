from django.contrib import admin
from .models import ScanSession, Finding


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    readonly_fields = (
        "id",
        "title",
        "scanner_name",
        "rule_id",
        "severity",
        "file_path",
        "line_number",
        "created_at",
    )
    can_delete = False


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "status",
        "project_path",
        "target_url",
        "total_findings",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "duration_seconds",
        "created_at",
    )
    list_filter = ("status", "created_at")
    search_fields = ("id", "project_path")
    readonly_fields = ("id", "created_at", "updated_at")
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "scanner_name",
        "severity",
        "file_path",
        "line_number",
        "rule_id",
        "scan_session",
        "created_at",
    )
    list_filter = ("severity", "scanner_name", "created_at")
    search_fields = ("title", "rule_id", "file_path", "description")
    readonly_fields = ("id", "created_at", "updated_at")
