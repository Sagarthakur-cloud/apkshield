from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from reportlab.pdfgen import canvas

from .models import APKScan
from .forms import SignupForm
from .analyzers import analyze_apk


# ═══════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════

def signup_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)
            messages.success(request, f"Welcome, {user.username}!")
            return redirect("dashboard")
    else:
        form = SignupForm()

    return render(request, "app/signup.html", {"form": form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, "app/login.html", {"form": form})


def logout_view(request):
    auth_logout(request)
    return redirect("login")


# ═══════════════════════════════════════════════
# MAIN PAGES (login required)
# ═══════════════════════════════════════════════

@login_required
def dashboard_view(request):
    return render(request, "app/index.html")


@login_required
def history_view(request):
    scans = APKScan.objects.filter(user=request.user)
    return render(request, "app/history.html", {"scans": scans})


@login_required
def report_view(request, scan_id=None):
    if scan_id:
        scan = get_object_or_404(APKScan, id=scan_id, user=request.user)
    else:
        scan = APKScan.objects.filter(user=request.user).first()
    return render(request, "app/report.html", {"scan": scan})


@login_required
def threats_view(request):
    return render(request, "app/threats.html")


@login_required
def settings_view(request):
    return render(request, "app/settings.html")


@login_required
def about_view(request):
    return render(request, "app/about.html")


# ═══════════════════════════════════════════════
# API — APK scan
# ═══════════════════════════════════════════════

@login_required
@require_POST
def api_scan_apk(request):
    """
    Receives an APK upload, analyzes it, saves a record,
    and returns the report as JSON.
    """
    file = request.FILES.get("file")
    if not file:
        return JsonResponse({"error": "No file provided"}, status=400)

    if not file.name.lower().endswith(".apk"):
        return JsonResponse({"error": "Only .apk files allowed"}, status=400)

    if file.size > 100 * 1024 * 1024:
        return JsonResponse({"error": "File too large (max 100 MB)"}, status=400)

    result = analyze_apk(file)

    scan = APKScan.objects.create(
        user=request.user,
        filename=file.name,
        package=result["package"],
        file_size=result["file_size"],
        sha256=result["sha256"],
        certificate=result["certificate"],
        risk_score=result["risk_score"],
        classification=result["classification"],
        malware_family=result["malware_family"],
        malware_category=result["malware_category"],
        ai_confidence=result["ai_confidence"],
        family_match=result["family_match"],
        breakdown=result["breakdown"],
        ai_summary=result["ai_summary"],
        recommendation=result["recommendation"],
        detected_risks=result["detected_risks"],
    )

    return JsonResponse({
        "id": str(scan.id),
        "filename": scan.filename,
        "package": scan.package,
        "size": f"{scan.file_size / (1024 * 1024):.2f} MB",
        "sha256": scan.sha256,
        "certificate": scan.certificate,
        "risk_score": scan.risk_score,
        "classification": scan.classification,
        "malware_family": scan.malware_family,
        "malware_category": scan.malware_category,
        "ai_confidence": scan.ai_confidence,
        "family_match": scan.family_match,
        "breakdown": scan.breakdown,
        "ai_summary": scan.ai_summary,
        "recommendation": scan.recommendation,
        "detected_risks": scan.detected_risks,
        "scan_date": scan.scan_date.isoformat(),
    })


@login_required
def api_history(request):
    """Return JSON list of the user's scans."""
    scans = APKScan.objects.filter(user=request.user)[:100]
    return JsonResponse({
        "scans": [
            {
                "id": str(s.id),
                "filename": s.filename,
                "package": s.package,
                "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M"),
                "risk_score": s.risk_score,
                "classification": s.classification,
                "malware_family": s.malware_family,
            }
            for s in scans
        ]
    })

