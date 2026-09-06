#!/usr/bin/env python3
"""Explicit test-message submission. No default recipient or automatic network send."""
import argparse
import smtplib
import ssl
from pathlib import Path

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("message", type=Path)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=25)
    p.add_argument("--helo", required=True)
    p.add_argument("--mail-from", required=True)
    p.add_argument("--recipient", required=True, help="A test address that you control")
    p.add_argument("--send", action="store_true", help="Actually send the one test message")
    a = p.parse_args()
    if not a.send:
        print("Prepared only. Review the host and recipient, then add --send to submit one message.")
        return
    data = a.message.read_bytes()
    if b"\r\n\r\n" not in data:
        raise ValueError("Provide an SMTP .eml with CRLF line endings")
    with smtplib.SMTP(a.host, a.port, local_hostname=a.helo, timeout=60) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        refused = smtp.sendmail(a.mail_from, [a.recipient], data)
        if refused:
            raise RuntimeError(refused)
    print("SMTP accepted the message. Verify arrival, folder and authentication in Proton separately.")

if __name__ == "__main__":
    main()
