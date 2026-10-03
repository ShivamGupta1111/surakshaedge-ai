"""Generate synthetic demo CSVs. Not real research data."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import PROJECT_ROOT

DATA = ROOT / "data"

SMS_ROWS = [
    ("Meeting moved to 4pm in conference room B.", "legitimate"),
    ("Your package will arrive tomorrow as scheduled.", "legitimate"),
    ("Can you review the attached notes from class?", "legitimate"),
    ("Dinner at 8? Let me know.", "legitimate"),
    ("The office wifi password was rotated; check the staff portal.", "legitimate"),
    ("See you at the cricket match on Sunday.", "legitimate"),
    ("Please bring your student ID to the lab tomorrow.", "legitimate"),
    ("Project deadline is Friday, no extensions.", "legitimate"),
    ("Mom, I reached campus safely.", "legitimate"),
    ("Invoice copy is in the shared drive folder invoices.", "legitimate"),
    ("School closed due to rain. Stay home.", "legitimate"),
    ("Your library book is due next week.", "legitimate"),
    ("Team standup moved to Google Meet using our usual link.", "legitimate"),
    ("Happy birthday! Cake in the pantry.", "legitimate"),
    ("Doctor appointment reminder for Thursday 11am.", "legitimate"),
    ("URGENT: your bank account will be suspended. Confirm password now.", "phishing"),
    ("Verify your account OTP immediately to avoid closure http://bit.ly/xx", "phishing"),
    ("IT department: send PIN and password to keep email active.", "phishing"),
    ("Amazon: unusual login. Share OTP to keep your wallet.", "phishing"),
    ("Income tax refund pending. Enter CVV and OTP here.", "phishing"),
    ("Microsoft security: password expires in 10 minutes. Reply with password.", "phishing"),
    ("Your KYC is incomplete. Send UPI PIN to resume payments.", "phishing"),
    ("CEO needs gift cards urgently. Buy and send codes now!!!", "scam"),
    ("Congratulations you won a lottery prize. Claim now or lose it.", "scam"),
    ("You are the lucky winner of 50 lakh. Pay processing fee today.", "scam"),
    ("Final notice: transfer money to this wallet to release parcel.", "scam"),
    ("Claim your free reward. Click tinyurl.com/prize immediately.", "scam"),
    ("Customs: pay duty via UPI or shipment destroyed.", "scam"),
    ("Cheap meds online click here www.not-a-real-pharmacy.xyz", "spam"),
    ("Win free data pack reply WIN to 5-digit short code.", "spam"),
    ("Exclusive deals just for you!!!!! visit promo site", "spam"),
    ("You have 1 new voicemail. Call this unknown number now.", "spam"),
]

URL_ROWS = [
    ("https://example.com/docs/help", "benign"),
    ("https://www.wikipedia.org/wiki/Computer_security", "benign"),
    ("https://github.com/python/cpython", "benign"),
    ("https://shop.example.org/products/shoes", "benign"),
    ("https://news.example.net/article/123", "benign"),
    ("https://university.example.edu/admissions", "benign"),
    ("https://maps.example.com/place", "benign"),
    ("https://docs.python.org/3/library/urllib.parse.html", "benign"),
    ("https://httpbin.org/get", "benign"),
    ("https://example.com/login", "benign"),
    ("http://192.0.2.55/login/verify-account/wallet", "malicious"),
    ("http://203.0.113.10/secure/update-password", "malicious"),
    ("http://198.51.100.8/wallet/verify", "malicious"),
    ("http://192.0.2.88/invoice/reward", "malicious"),
    ("http://secure-login-verify-account.xyz/wallet/update", "phishing_suspected"),
    ("http://bit.ly/not-a-real-short-link", "suspicious"),
    ("http://paypa1-secure-login.top/verify", "phishing_suspected"),
    ("http://xn--login-account.example.tk/secure", "suspicious"),
    ("http://reward-wallet-verify.gq/claim", "phishing_suspected"),
    ("http://update-billing-secure.xyz/password", "phishing_suspected"),
    ("http://login.login.login.verify.example.xyz/account", "suspicious"),
    ("https://example.com/%2e%2e/%2e%2e/etc", "suspicious"),
    ("http://win-free-reward.ml/invoice", "phishing_suspected"),
]

NET_HEADER = [
    "duration",
    "protocol",
    "src_port",
    "dst_port",
    "fwd_packets",
    "bwd_packets",
    "bytes_transferred",
    "packet_rate",
    "failed_count",
    "repeated_dst",
    "conn_freq",
    "syn_count",
    "rst_count",
    "label",
]


def network_rows() -> list[list[object]]:
    rows: list[list[object]] = []
    for i in range(16):
        rows.append([0.4 + i / 10, "tcp", 40000 + i, 443, 8, 10, 1500 + i * 10, 20, 0, 1, 2, 1, 0, "normal"])
    for i in range(8):
        rows.append([0.1, "tcp", 1234, 4444, 40, 0, 800, 2500, 12, 25, 60, 40, 5, "likely_intrusion"])
    for i in range(8):
        rows.append([1.0, "tcp", 2222, 8080, 20, 2, 4000, 500, 4, 8, 12, 10, 1, "suspicious"])
    return rows


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with (DATA / "sms_spam.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["text", "label"])
        writer.writerows(SMS_ROWS)
    with (DATA / "url_dataset.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        writer.writerows(URL_ROWS)
    with (DATA / "network_flows.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(NET_HEADER)
        writer.writerows(network_rows())
    with (DATA / "url_threat_intel.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "source"])
        writer.writerow(["paypa1-secure-login.top", "local-demo"])
    print("Wrote synthetic demo CSVs under data/. These are not real research datasets.")


if __name__ == "__main__":
    main()
