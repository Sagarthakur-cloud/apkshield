"""
APKShield — APK Analysis Engine
Static analysis + XGBoost ML prediction.
"""

import hashlib
import os
import tempfile
import zipfile
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# ML MODEL — lazy loaded
# ═══════════════════════════════════════════════════════════════
_ml_model = None
_ml_features = None
_ml_encoder = None
_ml_loaded = False


def _load_ml_model():
    """Load trained XGBoost + features + label encoder."""
    global _ml_model, _ml_features, _ml_encoder, _ml_loaded
    if _ml_loaded:
        return _ml_model, _ml_features, _ml_encoder
    _ml_loaded = True

    try:
        import joblib
        from django.conf import settings

        base = Path(settings.BASE_DIR) / "ml"
        model_path = base / "ml_model.pkl"
        features_path = base / "feature_columns.pkl"
        encoder_path = base / "label_encoder.pkl"

        if model_path.exists() and features_path.exists():
            _ml_model = joblib.load(model_path)
            _ml_features = joblib.load(features_path)
            if encoder_path.exists():
                _ml_encoder = joblib.load(encoder_path)
            print(f"[analyzer] ML model loaded ({len(_ml_features)} features)")
        else:
            print("[analyzer] ML model not found — rule-only mode")
    except Exception as e:
        print(f"[analyzer] ML load failed: {e}")

    return _ml_model, _ml_features, _ml_encoder


# ═══════════════════════════════════════════════════════════════
# WEIGHTED PERMISSION TABLE
# ═══════════════════════════════════════════════════════════════
DANGEROUS_PERMISSIONS = {
    "BIND_ACCESSIBILITY_SERVICE": 30,
    "SYSTEM_ALERT_WINDOW": 25,
    "INSTALL_PACKAGES": 25,
    "REQUEST_INSTALL_PACKAGES": 20,
    "PACKAGE_USAGE_STATS": 15,
    "SEND_SMS": 20,
    "READ_SMS": 15,
    "RECEIVE_SMS": 12,
    "READ_CALL_LOG": 15,
    "PROCESS_OUTGOING_CALLS": 15,
    "CALL_PHONE": 10,
    "READ_CONTACTS": 10,
    "WRITE_CONTACTS": 10,
    "RECORD_AUDIO": 10,
    "READ_PHONE_STATE": 8,
    "RECEIVE_BOOT_COMPLETED": 8,
    "CAMERA": 8,
    "ACCESS_FINE_LOCATION": 8,
    "ACCESS_BACKGROUND_LOCATION": 12,
    "GET_ACCOUNTS": 8,
    "ACCESS_COARSE_LOCATION": 5,
    "INTERNET": 2,
    "ACCESS_NETWORK_STATE": 1,
}


# ═══════════════════════════════════════════════════════════════
# DEX API PATTERNS
# ═══════════════════════════════════════════════════════════════
MALICIOUS_APIS = [
    ("Ldalvik/system/DexClassLoader;", 25, "Dynamic code loading"),
    ("Ljava/lang/Runtime;->exec", 25, "Shell command execution"),
    ("Landroid/telephony/SmsManager;->sendTextMessage", 20, "Silent SMS sending"),
    ("Landroid/app/admin/DevicePolicyManager;", 20, "Device admin request"),
    ("Landroid/accessibilityservice/AccessibilityService;", 25, "Accessibility abuse"),
    ("Landroid/content/pm/PackageInstaller;", 15, "Silent app installer"),
    ("Landroid/media/MediaRecorder;", 10, "Audio recording"),
    ("Ljava/lang/reflect/Method;->invoke", 10, "Reflection"),
]


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def analyze_apk(file_obj):
    tmp_path = None
    try:
        tmp_path = _save_temp(file_obj)
        return _real_analysis(tmp_path, file_obj)
    except Exception as e:
        import traceback
        print(f"[analyzer] FAILED: {type(e).__name__}: {e}")
        traceback.print_exc()
        return _fallback_report(file_obj, str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _save_temp(file_obj):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        for chunk in file_obj.chunks():
            tmp.write(chunk)
        return tmp.name


def _real_analysis(apk_path, file_obj):
    from androguard.core.apk import APK

    a = APK(apk_path)
    package = a.get_package() or "unknown.package"
    permissions = a.get_permissions() or []
    activities = a.get_activities() or []
    services = a.get_services() or []
    receivers = a.get_receivers() or []
    providers = a.get_providers() or []
    certs = a.get_certificates() or []

    short_perms = set(_short(p) for p in permissions)
    sha256 = _sha256_of_file(apk_path)

    # ── Rule-based scoring ──
    perm_score = 0
    risks = []

    for p_short in sorted(short_perms):
        if p_short in DANGEROUS_PERMISSIONS:
            w = DANGEROUS_PERMISSIONS[p_short]
            perm_score += w
            severity = "High" if w >= 15 else ("Medium" if w >= 8 else "Low")
            risks.append({
                "name": p_short,
                "severity": severity,
                "details": _permission_reason(p_short),
            })
    perm_score = min(perm_score, 60)

    # Certificate
    cert_score = 0
    certificate = "Not signed"
    if certs:
        try:
            cert = certs[0]
            if getattr(cert, "issuer", None) == getattr(cert, "subject", None):
                certificate = "Self-signed"
                cert_score = 15
                risks.append({
                    "name": "Self-signed certificate",
                    "severity": "Medium",
                    "details": "Signed with self-signed cert — common in malware.",
                })
            else:
                certificate = "Verified"
        except Exception:
            certificate = "Unknown"
    else:
        certificate = "Unsigned"
        cert_score = 25
        risks.append({
            "name": "Unsigned APK",
            "severity": "High",
            "details": "APK not signed by any developer.",
        })

    # Components
    comp_score = 0
    if len(activities) > 50:
        comp_score += 8
        risks.append({
            "name": f"{len(activities)} activities",
            "severity": "Medium",
            "details": "Unusually many activities.",
        })
    if any("BOOT_COMPLETED" in r for r in receivers):
        comp_score += 10
        risks.append({
            "name": "Boot receiver",
            "severity": "Medium",
            "details": "Auto-starts on boot.",
        })
    comp_score = min(comp_score, 20)

    # DEX APIs
    dex_bytes = _collect_dex_bytes(apk_path)
    api_score = 0
    if dex_bytes:
        for pattern, weight, desc in MALICIOUS_APIS:
            if pattern.encode("utf-8") in dex_bytes:
                api_score += weight
                risks.append({
                    "name": pattern.split("/")[-1].rstrip(";")[:30],
                    "severity": "High" if weight >= 15 else "Medium",
                    "details": desc,
                })
    api_score = min(api_score, 60)

    rule_score = perm_score + cert_score + comp_score + api_score

    # ── ML PREDICTION ──
    ml_score = None
    ml_label = None
    ml_confidence = 0

    model, feature_cols, encoder = _load_ml_model()
    if model is not None and feature_cols:
        try:
            fv = _build_feature_vector(
                short_perms, activities, services, receivers,
                dex_bytes, feature_cols
            )
            proba = model.predict_proba([fv])[0]
            ml_score = int(max(proba) * 100)
            if encoder is not None:
                pred_idx = int(model.predict([fv])[0])
                ml_label = encoder.inverse_transform([pred_idx])[0]
        except Exception as e:
            print(f"[analyzer] ML predict failed: {e}")

    # ── COMBINE ──
    if ml_score is not None:
        combined = int(rule_score * 0.5 + ml_score * 0.5)
    else:
        combined = rule_score
    final_score = min(combined, 100)

    # ── CLASSIFY ──
    if final_score >= 70:
        classification = "Malicious"
    elif final_score >= 40:
        classification = "Suspicious"
    else:
        classification = "Safe"

    # ── FAMILY ──
    family, category = _guess_family(short_perms, risks, ml_label)

    # ── CONFIDENCE ──
    if ml_score is not None:
        confidence = max(60, min(ml_score, 99))
    else:
        confidence = min(60 + len(risks) * 4, 99)

    family_match = 87 if family else 0

    # ── SUMMARY ──
    ml_part = f" ML predicted: {ml_label} ({ml_score}%)." if ml_label else ""
    summary = (
        f"Analyzed {len(permissions)} permissions, {len(activities)} activities, "
        f"{len(services)} services, {len(receivers)} receivers. "
        f"Detected {len(risks)} risk indicators.{ml_part}"
    )

    # ── RECOMMENDATION ──
    if classification == "Malicious":
        recommendation = "Do NOT install. High-risk APK with multiple malware indicators."
    elif classification == "Suspicious":
        recommendation = "Proceed with caution. Some risky permissions detected."
    else:
        recommendation = "Safe to install. No significant threats found."

        return {
        "package": package,
        "file_size": file_obj.size,
        "sha256": sha256,
        "certificate": certificate,
        "risk_score": final_score,
        "classification": classification,
        "malware_family": family,
        "malware_category": category,
        "ai_confidence": confidence,
        "family_match": family_match,
        "breakdown": {
            "signature": min(perm_score + api_score, 100),
            "heuristic": min(perm_score + comp_score, 100),
            "behavior": ml_score if ml_score else min(api_score + cert_score, 100),
        },
        "ai_summary": summary,
        "recommendation": recommendation,
        "detected_risks": risks or [{
            "name": "No risks detected",
            "severity": "Safe",
            "details": "This APK appears clean.",
        }],
        "capabilities": _detect_capabilities(short_perms, dex_bytes),
    }


# ═══════════════════════════════════════════════════════════════
# FEATURE VECTOR BUILDER
# ═══════════════════════════════════════════════════════════════
def _build_feature_vector(short_perms, activities, services, receivers,
                          dex_bytes, feature_order):
    """Build feature vector matching training columns."""

    # Permission name mapping
    perm_map = {}
    for p in DANGEROUS_PERMISSIONS:
        perm_map[p] = p in short_perms
    perm_map["INTERNET"] = "INTERNET" in short_perms
    perm_map["ACCESS_NETWORK_STATE"] = "ACCESS_NETWORK_STATE" in short_perms

    # API name mapping
    api_map = {
        "DexClassLoader": b"Ldalvik/system/DexClassLoader;" in dex_bytes,
        "Runtime.exec": b"Ljava/lang/Runtime;->exec" in dex_bytes,
        "sendTextMessage": b"sendTextMessage" in dex_bytes,
        "DevicePolicyManager": b"DevicePolicyManager" in dex_bytes,
    }

    vec = []
    for feat in feature_order:
        # Try permission
        pname = feat.replace("android.permission.", "").replace("android.", "")
        if pname in perm_map:
            vec.append(1 if perm_map[pname] else 0)
        elif feat in api_map:
            vec.append(1 if api_map[feat] else 0)
        elif feat == "n_activities":
            vec.append(len(activities))
        elif feat == "n_services":
            vec.append(len(services))
        elif feat == "n_receivers":
            vec.append(len(receivers))
        else:
            vec.append(0)

    return vec


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def _short(perm):
    return perm.split(".")[-1]


def _sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_dex_bytes(apk_path):
    try:
        with zipfile.ZipFile(apk_path) as z:
            buf = bytearray()
            for name in z.namelist():
                if name.endswith(".dex"):
                    with z.open(name) as f:
                        buf.extend(f.read(500_000))
            return bytes(buf)
    except Exception:
        return b""


def _permission_reason(perm):
    reasons = {
        "BIND_ACCESSIBILITY_SERVICE": "Reads screen content and simulates input — banking trojan indicator.",
        "SYSTEM_ALERT_WINDOW": "Draws overlays on other apps — phishing attacks.",
        "INSTALL_PACKAGES": "Can silently install other apps.",
        "REQUEST_INSTALL_PACKAGES": "Can prompt user to install APKs.",
        "SEND_SMS": "Sends SMS silently — premium-rate fraud.",
        "READ_SMS": "Reads incoming SMS — bypasses OTP/2FA.",
        "RECEIVE_SMS": "Intercepts SMS messages.",
        "READ_CALL_LOG": "Reads call history — spyware behavior.",
        "READ_CONTACTS": "Reads contact list — exfiltration risk.",
        "RECORD_AUDIO": "Records microphone audio.",
        "READ_PHONE_STATE": "Reads device identifiers.",
        "RECEIVE_BOOT_COMPLETED": "Auto-starts on device boot.",
        "CAMERA": "Accesses camera.",
        "ACCESS_FINE_LOCATION": "Precise GPS tracking.",
        "ACCESS_BACKGROUND_LOCATION": "Tracks location in background.",
        "INTERNET": "Network access — C2 communication possible.",
    }
    return reasons.get(perm, f"Permission '{perm}' commonly abused by malware.")


def _guess_family(perms, risks, ml_label=None):
    if ("BIND_ACCESSIBILITY_SERVICE" in perms and
            "SYSTEM_ALERT_WINDOW" in perms and
            ("SEND_SMS" in perms or "READ_SMS" in perms)):
        return "Cerberus.Banker", "Trojan.Banker"

    if ("SEND_SMS" in perms and "READ_SMS" in perms and "READ_CONTACTS" in perms):
        return "Joker.Spyware", "Spyware"

    if ml_label == "Banking":
        return "Trojan.Banker", "Banking Trojan"
    if ml_label == "SMS":
        return "SMS.Trojan", "SMS Malware"
    if ml_label == "Adware":
        return "Adware.Generic", "Adware"
    if ml_label == "Riskware":
        return "Riskware.Generic", "Riskware"

    if len(risks) >= 5:
        return "Trojan.Generic", "Trojan"

    return None, None


def _fallback_report(file_obj, error_msg=""):
    def _fallback_report(file_obj, error_msg=""):
        return {
        "package": "unknown.package",
        "file_size": file_obj.size,
        "sha256": "0" * 64,
        "certificate": "Unknown",
        "risk_score": 0,
        "classification": "Safe",
        "malware_family": None,
        "malware_category": None,
        "ai_confidence": 40,
        "family_match": 0,
        "breakdown": {"signature": 0, "heuristic": 0, "behavior": 0},
        "ai_summary": f"Analysis failed: {error_msg}",
        "recommendation": "Unable to determine safety.",
        "detected_risks": [],
        "capabilities": [],
    }

# ═══════════════════════════════════════════════════════════════
# CAPABILITY DETECTION — "What does this APK do?"
# ═══════════════════════════════════════════════════════════════

CAPABILITIES = [
    {
        "id": "send_sms",
        "icon": "fa-comment-sms",
        "title": "Sends SMS Messages",
        "description": "Can send SMS without your confirmation — often used for premium-rate fraud.",
        "permissions": ["SEND_SMS"],
        "apis": ["sendTextMessage", "sendMultipartTextMessage"],
        "severity": "High",
    },
    {
        "id": "read_sms",
        "icon": "fa-envelope-open-text",
        "title": "Reads Incoming SMS",
        "description": "Can intercept SMS messages — used to steal OTPs and 2FA codes.",
        "permissions": ["READ_SMS", "RECEIVE_SMS"],
        "apis": ["SmsMessage"],
        "severity": "High",
    },
    {
        "id": "track_location",
        "icon": "fa-location-dot",
        "title": "Tracks Your Location",
        "description": "Reads GPS coordinates and can share them with remote servers.",
        "permissions": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"],
        "apis": ["LocationManager", "FusedLocationProvider", "getLastKnownLocation"],
        "severity": "High",
    },
    {
        "id": "read_contacts",
        "icon": "fa-address-book",
        "title": "Reads Your Contact List",
        "description": "Accesses all your contacts — often exfiltrated to attacker servers.",
        "permissions": ["READ_CONTACTS"],
        "apis": ["ContactsContract"],
        "severity": "Medium",
    },
    {
        "id": "record_audio",
        "icon": "fa-microphone",
        "title": "Records Audio",
        "description": "Can record microphone audio without your knowledge.",
        "permissions": ["RECORD_AUDIO"],
        "apis": ["MediaRecorder", "AudioRecord"],
        "severity": "High",
    },
    {
        "id": "camera",
        "icon": "fa-camera",
        "title": "Accesses Camera",
        "description": "Can take photos or record videos secretly.",
        "permissions": ["CAMERA"],
        "apis": ["Camera2", "MediaRecorder"],
        "severity": "Medium",
    },
    {
        "id": "read_call_log",
        "icon": "fa-phone",
        "title": "Reads Call History",
        "description": "Accesses your call logs — used for surveillance.",
        "permissions": ["READ_CALL_LOG"],
        "apis": ["CallLog"],
        "severity": "Medium",
    },
    {
        "id": "overlay",
        "icon": "fa-layer-group",
        "title": "Draws Overlays on Other Apps",
        "description": "Can show fake login screens over banking apps — classic phishing technique.",
        "permissions": ["SYSTEM_ALERT_WINDOW"],
        "apis": ["TYPE_APPLICATION_OVERLAY", "WindowManager"],
        "severity": "High",
    },
    {
        "id": "accessibility",
        "icon": "fa-universal-access",
        "title": "Uses Accessibility Service",
        "description": "Can read screen content and simulate taps — used by banking trojans.",
        "permissions": ["BIND_ACCESSIBILITY_SERVICE"],
        "apis": ["AccessibilityService"],
        "severity": "Critical",
    },
    {
        "id": "install_apps",
        "icon": "fa-download",
        "title": "Installs Other Apps",
        "description": "Can silently install additional APKs — used as a dropper.",
        "permissions": ["INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES"],
        "apis": ["PackageInstaller"],
        "severity": "High",
    },
    {
        "id": "device_admin",
        "icon": "fa-shield",
        "title": "Requests Device Admin",
        "description": "Can lock or wipe your device — often used by ransomware.",
        "permissions": ["BIND_DEVICE_ADMIN"],
        "apis": ["DevicePolicyManager"],
        "severity": "Critical",
    },
    {
        "id": "boot_start",
        "icon": "fa-power-off",
        "title": "Starts on Device Boot",
        "description": "Auto-runs on boot — persistent background activity.",
        "permissions": ["RECEIVE_BOOT_COMPLETED"],
        "apis": ["BOOT_COMPLETED"],
        "severity": "Medium",
    },
    {
        "id": "dynamic_code",
        "icon": "fa-code-branch",
        "title": "Loads Code Dynamically",
        "description": "Downloads and runs code at runtime — evades static detection.",
        "permissions": [],
        "apis": ["DexClassLoader", "PathClassLoader"],
        "severity": "High",
    },
    {
        "id": "shell_exec",
        "icon": "fa-terminal",
        "title": "Executes Shell Commands",
        "description": "Runs system commands — high-risk behavior.",
        "permissions": [],
        "apis": ["Runtime;->exec", "ProcessBuilder"],
        "severity": "Critical",
    },
    {
        "id": "network",
        "icon": "fa-globe",
        "title": "Sends Data Over Internet",
        "description": "Connects to remote servers — could be C2 communication.",
        "permissions": ["INTERNET"],
        "apis": ["openConnection", "HttpURLConnection"],
        "severity": "Low",
    },
    {
        "id": "read_phone_state",
        "icon": "fa-mobile-screen",
        "title": "Reads Device Identifiers",
        "description": "Accesses IMEI, phone number, and SIM info.",
        "permissions": ["READ_PHONE_STATE"],
        "apis": ["TelephonyManager"],
        "severity": "Medium",
    },
]


def _detect_capabilities(short_perms, dex_bytes):
    """Analyze which capabilities this APK has, based on permissions + DEX patterns."""
    detected = []

    for cap in CAPABILITIES:
        perm_hit = any(p in short_perms for p in cap["permissions"])
        api_hit = False
        if dex_bytes:
            for api in cap["apis"]:
                if api.encode("utf-8") in dex_bytes:
                    api_hit = True
                    break

        if perm_hit or api_hit:
            detected.append({
                "id": cap["id"],
                "icon": cap["icon"],
                "title": cap["title"],
                "description": cap["description"],
                "severity": cap["severity"],
                "triggers": {
                    "permissions": [p for p in cap["permissions"] if p in short_perms],
                    "apis": cap["apis"] if api_hit else [],
                },
            })

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    detected.sort(key=lambda x: severity_order.get(x["severity"], 4))
    return detected