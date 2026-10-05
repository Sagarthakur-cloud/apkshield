from django.views.decorators.cache import never_cache
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from reportlab.pdfgen import canvas
import requests
import json 
import tempfile
import os
try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:  # pragma: no cover - handled at runtime
    BeautifulSoup = None
from urllib.parse import urlparse, parse_qs

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
    return redirect("welcome")


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
        capabilities=result.get("capabilities", []),
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
        "capabilities": scan.capabilities,
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

# ═══════════════════════════════════════════════
# PLAY STORE SCAN
# ═══════════════════════════════════════════════

@login_required
@require_POST
def api_scan_playstore(request):
    """Download and scan an APK from a Play Store URL."""
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"error": "Invalid request body"}, status=400)

    play_url = (data.get("url") or "").strip()
    if not play_url:
        return JsonResponse({"error": "No URL provided"}, status=400)

    # Extract package name from URL
    try:
        parsed = urlparse(play_url)
        qs = parse_qs(parsed.query)
        package = (qs.get("id") or [None])[0]
        if not package:
            # Try alternate format: /store/apps/details/com.example.app
            path_parts = parsed.path.strip("/").split("/")
            if "details" in path_parts:
                idx = path_parts.index("details")
                if idx + 1 < len(path_parts):
                    package = path_parts[idx + 1]
    except Exception as e:
        return JsonResponse({"error": f"URL parse error: {e}"}, status=400)

    if not package:
        return JsonResponse({
            "error": "Could not extract package name. Use format: play.google.com/store/apps/details?id=com.example.app"
        }, status=400)

    # ── Download APK ──
    try:
        apk_bytes = _download_apk_from_apkcombo(package)
    except Exception as e:
        return JsonResponse({"error": f"Download failed: {e}"}, status=500)

    if BeautifulSoup is None:
        return JsonResponse({"error": "Missing dependency: beautifulsoup4. Install requirements to enable Play Store APK downloads."}, status=500)

    if not apk_bytes:
        # Fallback: check local prefetched APKs
        local_path = os.path.join("media", "prefetched_apks", f"{package}.apk")
        if os.path.exists(local_path):
            with open(local_path, "rb") as f:
                apk_bytes = f.read()
        else:
            return JsonResponse({
                "error": f"Could not download APK for '{package}'. Try uploading the APK file manually."
            }, status=404)

    # ── Save temporarily ──
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(apk_bytes)
        tmp_path = tmp.name

    # ── Analyze ──
    try:
        from .analyzers import _real_analysis

        class _FakeFile:
            def __init__(self, path, size):
                self._path = path
                self.size = size
            def chunks(self):
                with open(self._path, "rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        yield chunk

        fake = _FakeFile(tmp_path, len(apk_bytes))
        result = _real_analysis(tmp_path, fake)

        scan = APKScan.objects.create(
            user=request.user,
            filename=f"{package}.apk",
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
            capabilities=result.get("capabilities", []),
            status="completed",
            progress=100,
        )

        return JsonResponse({
            "id": str(scan.id),
            "filename": scan.filename,
            "package": scan.package,
            "size": f"{scan.file_size / (1024*1024):.2f} MB",
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
            "source": "Play Store",
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": f"Analysis failed: {e}"}, status=500)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _download_apk_from_apkcombo(package_name):
    """Download an APK via APKCombo scraping with retries and longer timeouts."""
    if BeautifulSoup is None:
        raise RuntimeError("BeautifulSoup is not installed.")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # ═══════════════════════════════════════════════
    # RETRY WRAPPER
    # ═══════════════════════════════════════════════
    def fetch_with_retry(url, timeout=30, max_retries=2, stream=False):
        """Try fetching a URL with retries. Returns Response or None."""
        for attempt in range(1, max_retries + 1):
            try:
                print(f"[apkcombo] Attempt {attempt}/{max_retries}: {url}")
                res = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    stream=stream,
                    allow_redirects=True,
                )
                print(f"[apkcombo] Response: {res.status_code}")
                if res.status_code == 200:
                    return res
                else:
                    print(f"[apkcombo] Non-200 status: {res.status_code}")
            except requests.exceptions.Timeout:
                print(f"[apkcombo] Attempt {attempt} timeout ({timeout}s)")
            except requests.exceptions.ConnectionError as e:
                print(f"[apkcombo] Attempt {attempt} connection error: {e}")
            except Exception as e:
                print(f"[apkcombo] Attempt {attempt} failed: {type(e).__name__}: {e}")

            if attempt < max_retries:
                import time
                time.sleep(2)  # wait 2 sec before retry

        return None

    # ═══════════════════════════════════════════════
    # STEP 1 — Search Page
    # ═══════════════════════════════════════════════
    search_url = f"https://apkcombo.com/search/{package_name}"
    res = fetch_with_retry(search_url, timeout=30, max_retries=2)
    if not res:
        print(f"[apkcombo] Failed to reach search page")
        return None

    soup = BeautifulSoup(res.text, "html.parser")
    link = soup.select_one(f"a[href*='/{package_name}/']")
    if not link:
        link = soup.select_one(f"a[href*='{package_name}']")
    if not link:
        print(f"[apkcombo] No search result found for {package_name}")
        return None

    detail_url = link["href"]
    if not detail_url.startswith("http"):
        detail_url = "https://apkcombo.com" + detail_url

    # ═══════════════════════════════════════════════
    # STEP 2 — Detail Page
    # ═══════════════════════════════════════════════
    detail = fetch_with_retry(detail_url, timeout=30, max_retries=2)
    if not detail:
        print(f"[apkcombo] Failed to reach detail page")
        return None

    detail_soup = BeautifulSoup(detail.text, "html.parser")
    dl_link = detail_soup.select_one("a[href*='/download/']")
    if not dl_link:
        # Try alternative selectors
        dl_link = detail_soup.select_one("a.download-btn")
    if not dl_link:
        print(f"[apkcombo] No download link found on detail page")
        return None

    dl_url = dl_link["href"]
    if not dl_url.startswith("http"):
        dl_url = "https://apkcombo.com" + dl_url

    # ═══════════════════════════════════════════════
    # STEP 3 — Download Page
    # ═══════════════════════════════════════════════
    dl_page = fetch_with_retry(dl_url, timeout=30, max_retries=2)
    if not dl_page:
        print(f"[apkcombo] Failed to reach download page")
        return None

    dl_soup = BeautifulSoup(dl_page.text, "html.parser")

    # Look for direct .apk link
    apk_link = dl_soup.select_one("a[href$='.apk']")
    if not apk_link:
        apk_link = dl_soup.select_one("a[href*='.apk']")
    if not apk_link:
        # Try meta refresh or JS redirect
        meta = dl_soup.select_one("meta[http-equiv='refresh']")
        if meta and "url=" in meta.get("content", "").lower():
            # Extract URL from meta refresh
            content = meta["content"]
            url_part = content.split("url=")[-1].strip()
            if url_part.startswith("http"):
                apk_link = {"href": url_part}

    if not apk_link:
        print(f"[apkcombo] No direct APK link found")
        return None

    apk_url = apk_link["href"] if isinstance(apk_link, dict) else apk_link["href"]
    if not apk_url.startswith("http"):
        apk_url = "https://apkcombo.com" + apk_url

    # ═══════════════════════════════════════════════
    # STEP 4 — Download the APK file (with retry)
    # ═══════════════════════════════════════════════
    apk_res = fetch_with_retry(apk_url, timeout=120, max_retries=2, stream=True)
    if not apk_res:
        print(f"[apkcombo] Failed to download APK file")
        return None

    # Read content in chunks
    content = b""
    try:
        for chunk in apk_res.iter_content(chunk_size=65536):
            if chunk:
                content += chunk
            # Cap at 100 MB
            if len(content) > 100 * 1024 * 1024:
                print(f"[apkcombo] File too large (>100MB), stopping")
                break
    except Exception as e:
        print(f"[apkcombo] Error reading chunks: {e}")
        return None

    print(f"[apkcombo] Downloaded {len(content) / (1024*1024):.2f} MB")

    # Verify it's actually a ZIP (APK = ZIP)
    if not content.startswith(b"PK"):
        print(f"[apkcombo] Downloaded file is not a valid APK (ZIP signature missing)")
        return None

    print(f"[apkcombo] ✓ Valid APK downloaded")
    return content

# ═══════════════════════════════════════════════
# WELCOME / LANDING PAGE
# ═══════════════════════════════════════════════

@never_cache
def welcome_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "app/welcome.html")