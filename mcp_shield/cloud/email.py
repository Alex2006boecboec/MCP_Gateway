"""Email service for transactional emails (password reset, notifications).

Supports two backends:
  1. SMTP  (Brevo, SendGrid, Gmail, etc.) — set MCP_SHIELD_SMTP_* env vars
  2. Console/log  (default, for dev/testing) — prints email to stderr

Configuration (env vars):
  MCP_SHIELD_SMTP_HOST       - SMTP server host (e.g. smtp-relay.brevo.com)
  MCP_SHIELD_SMTP_PORT       - SMTP server port (default 587)
  MCP_SHIELD_SMTP_USER       - SMTP username
  MCP_SHIELD_SMTP_PASSWORD   - SMTP password / API key
  MCP_SHIELD_SMTP_FROM       - From email address (e.g. noreply@yourdomain.com)
  MCP_SHIELD_SMPT_FROM_NAME  - From display name (default "MCP Shield")
  MCP_SHIELD_SMTP_USE_TLS    - "true" for STARTTLS (default), "false" to disable
  MCP_SHIELD_APP_URL         - Base URL of the dashboard (for reset links)
                               e.g. https://mcp-shield.up.railway.app

If MCP_SHIELD_SMTP_HOST is not set, emails are logged to stderr (dev mode).
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

log = logging.getLogger("mcp_shield.cloud.email")

# Singleton instance (initialized on first use).
_instance: Optional["EmailService"] = None


class EmailService:
    """Sends transactional emails via SMTP or logs to stderr (dev mode)."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 587,
        user: Optional[str] = None,
        password: Optional[str] = None,
        from_addr: Optional[str] = None,
        from_name: str = "MCP Shield",
        use_tls: bool = True,
        app_url: str = "http://localhost:8000",
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_addr = from_addr or "noreply@mcp-shield.local"
        self.from_name = from_name
        self.use_tls = use_tls
        self.app_url = app_url.rstrip("/")
        self.enabled = host is not None

    @classmethod
    def from_env(cls) -> "EmailService":
        """Create an EmailService from environment variables."""
        return cls(
            host=os.environ.get("MCP_SHIELD_SMTP_HOST"),
            port=int(os.environ.get("MCP_SHIELD_SMTP_PORT", "587")),
            user=os.environ.get("MCP_SHIELD_SMTP_USER"),
            password=os.environ.get("MCP_SHIELD_SMTP_PASSWORD"),
            from_addr=os.environ.get("MCP_SHIELD_SMTP_FROM"),
            from_name=os.environ.get("MCP_SHIELD_SMTP_FROM_NAME", "MCP Shield"),
            use_tls=os.environ.get("MCP_SHIELD_SMTP_USE_TLS", "true").lower() == "true",
            app_url=os.environ.get("MCP_SHIELD_APP_URL", "http://localhost:8000"),
        )

    def send(
        self,
        to: str,
        subject: str,
        text_body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send an email. Returns True on success, False on failure."""
        if not self.enabled:
            # Dev mode: log to stderr instead of sending.
            import sys
            print(f"\n{'='*50}", file=sys.stderr)
            print(f"  [DEV EMAIL] To: {to}", file=sys.stderr)
            print(f"  [DEV EMAIL] Subject: {subject}", file=sys.stderr)
            print(f"  [DEV EMAIL] Body:", file=sys.stderr)
            print(text_body, file=sys.stderr)
            print(f"{'='*50}\n", file=sys.stderr)
            return True

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.from_name} <{self.from_addr}>"
        msg["To"] = to
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        if html_body:
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            if self.use_tls:
                server = smtplib.SMTP(self.host, self.port, timeout=30)
                server.ehlo()
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=30)
                server.ehlo()

            if self.user and self.password:
                server.login(self.user, self.password)

            server.sendmail(self.from_addr, [to], msg.as_string())
            server.quit()
            log.info("email sent to %s: %s", to, subject)
            return True
        except Exception as e:
            log.error("email send failed to %s: %s", to, e)
            return False

    def send_password_reset(self, to: str, token: str) -> bool:
        """Send a password reset email with a reset link."""
        reset_url = f"{self.app_url}/reset?token={token}"
        subject = "MCP Shield — Password Reset"
        text = f"""\
Hello,

You requested a password reset for your MCP Shield account.

Reset your password by visiting:
{reset_url}

This link expires in 1 hour.

If you did not request this reset, you can safely ignore this email.

— MCP Shield Security
"""
        html = f"""\
<html><body>
<h2>Password Reset</h2>
<p>You requested a password reset for your MCP Shield account.</p>
<p><a href="{reset_url}" style="display:inline-block;padding:12px 24px;background:#6366f1;color:#fff;text-decoration:none;border-radius:6px;font-weight:bold;">Reset Password</a></p>
<p style="color:#666;font-size:14px;">Or copy this link: {reset_url}</p>
<p style="color:#999;font-size:13px;">This link expires in 1 hour. If you did not request this reset, you can safely ignore this email.</p>
<hr><p style="color:#999;font-size:12px;">MCP Shield Security</p>
</body></html>
"""
        return self.send(to, subject, text, html)


def get_email_service() -> EmailService:
    """Get the singleton EmailService instance (initialized from env on first call)."""
    global _instance
    if _instance is None:
        _instance = EmailService.from_env()
    return _instance
