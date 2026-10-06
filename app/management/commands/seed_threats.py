from django.core.management.base import BaseCommand
from app.models import MalwareFamily


THREATS = [
    {
        "name": "Cerberus",
        "category": "Banking Trojan",
        "severity": "Critical",
        "icon": "fa-building-columns",
        "signatures": 142,
        "last_seen": "2023",
        "first_seen": "2019-06",
        "targets": "Banking apps",
        "tags": ["overlay", "keylogging", "SMS fraud"],
        "description": "Android banking trojan using overlay attacks to steal credentials from banking apps.",
        "attack_vector": "Repackaged apps distributed via phishing SMS, fake Google Play listings, and third-party APK sites.",
        "permissions_abused": ["READ_SMS", "SYSTEM_ALERT_WINDOW", "READ_CONTACTS", "RECEIVE_SMS", "INTERNET"],
        "mitigation": "Avoid sideloading APKs from untrusted sources. Disable 'Install unknown apps'. Enable 2FA on banking apps.",
    },
    {
        "name": "Joker",
        "category": "Spyware",
        "severity": "High",
        "icon": "fa-face-grin-tongue-squint",
        "signatures": 98,
        "last_seen": "2024",
        "first_seen": "2017-03",
        "targets": "SMS & subscriptions",
        "tags": ["SMS fraud", "premium subscription"],
        "description": "Silently subscribes users to premium SMS services without consent.",
        "attack_vector": "Malicious apps sneaked into Google Play disguised as photo editors and utility tools.",
        "permissions_abused": ["RECEIVE_SMS", "READ_SMS", "SEND_SMS", "INTERNET", "READ_CONTACTS"],
        "mitigation": "Monitor phone bill closely. Block premium SMS with carrier.",
    },
    {
        "name": "Anubis",
        "category": "Banking Trojan",
        "severity": "Critical",
        "icon": "fa-eye-slash",
        "signatures": 121,
        "last_seen": "2024",
        "first_seen": "2017-06",
        "targets": "Banking & crypto apps",
        "tags": ["ransomware", "keylogging", "overlay", "accessibility abuse"],
        "description": "Full RAT with ransomware and keylogging capabilities. Uses Accessibility Service abuse.",
        "attack_vector": "Fake Google Play pages, phishing WhatsApp messages, dropper apps.",
        "permissions_abused": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_SMS", "CAMERA"],
        "mitigation": "Never grant Accessibility permission to unknown apps.",
    },
    {
        "name": "HiddenAds",
        "category": "Adware",
        "severity": "Medium",
        "icon": "fa-bullhorn",
        "signatures": 76,
        "last_seen": "2023",
        "first_seen": "2020-01",
        "targets": "Consumer devices",
        "tags": ["ad fraud", "device fingerprinting"],
        "description": "Displays intrusive full-screen ads and harvests device identifiers.",
        "attack_vector": "Bundled with games, VPNs, and utility apps on Google Play.",
        "permissions_abused": ["INTERNET", "READ_PHONE_STATE", "ACCESS_NETWORK_STATE"],
        "mitigation": "Uninstall apps that show ads outside their UI.",
    },
    {
        "name": "FakeApp",
        "category": "Trojan",
        "severity": "High",
        "icon": "fa-user-xmark",
        "signatures": 64,
        "last_seen": "2023",
        "first_seen": "2018-09",
        "targets": "General users",
        "tags": ["dropper", "repackaging"],
        "description": "Disguises itself as popular apps to drop secondary payloads.",
        "attack_vector": "Third-party APK sites, Telegram channels, malicious ads.",
        "permissions_abused": ["INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "INTERNET"],
        "mitigation": "Only install apps from official stores.",
    },
    {
        "name": "FluBot",
        "category": "Spyware",
        "severity": "Critical",
        "icon": "fa-comment-sms",
        "signatures": 89,
        "last_seen": "2023",
        "first_seen": "2021-03",
        "targets": "Banking & messaging",
        "tags": ["SMS worm", "credential theft", "contact harvesting"],
        "description": "Spreads via SMS with fake delivery notifications. Self-propagates to contacts.",
        "attack_vector": "Smishing (SMS phishing) with fake DHL/FedEx notifications.",
        "permissions_abused": ["READ_CONTACTS", "SEND_SMS", "READ_SMS", "BIND_ACCESSIBILITY_SERVICE"],
        "mitigation": "Never click links in unexpected SMS. Report smishing to 7726.",
    },
    {
        "name": "Harly",
        "category": "Trojan",
        "severity": "High",
        "icon": "fa-bolt",
        "signatures": 51,
        "last_seen": "2024",
        "first_seen": "2022-04",
        "targets": "Consumer devices",
        "tags": ["premium SMS", "subscription fraud"],
        "description": "Silently subscribes users to premium SMS services and installs additional apps.",
        "attack_vector": "Third-party app stores and repackaged games.",
        "permissions_abused": ["SEND_SMS", "READ_PHONE_STATE", "RECEIVE_BOOT_COMPLETED"],
        "mitigation": "Monitor phone bill closely. Block premium SMS with carrier.",
    },
    {
        "name": "Xenomorph",
        "category": "Banking Trojan",
        "severity": "Critical",
        "icon": "fa-skull",
        "signatures": 77,
        "last_seen": "2024",
        "first_seen": "2022-02",
        "targets": "56 banking apps",
        "tags": ["accessibility abuse", "overlay", "ATS"],
        "description": "Targets 56 banking apps across Europe using Accessibility Service abuse and ATS.",
        "attack_vector": "Distributed via droppers on Google Play disguised as productivity apps.",
        "permissions_abused": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_SMS"],
        "mitigation": "Monitor Accessibility Service permissions. Enable transaction alerts.",
    },
]


class Command(BaseCommand):
    help = "Seed the MalwareFamily database with known Android malware families"

    def handle(self, *args, **options):
        created = 0
        updated = 0

        for threat in THREATS:
            obj, was_created = MalwareFamily.objects.update_or_create(
                name=threat["name"],
                defaults=threat,
            )
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS(
            f"✓ Seeded {created} new families, updated {updated} existing."
        ))
        self.stdout.write(f"  Total families in DB: {MalwareFamily.objects.count()}")