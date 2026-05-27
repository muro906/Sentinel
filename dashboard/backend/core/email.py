"""Email service for sending notifications to users.

Supports SMTP for production and console/logging for development.
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Email service for sending notifications."""
    
    def __init__(self):
        """Initialize email service with SMTP settings from config."""
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
        self.enabled = all([self.smtp_user, self.smtp_password])
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """Send an email to a user.
        
        Args:
            to_email: Recipient email address.
            subject: Email subject.
            html_content: HTML body content.
            text_content: Plain text fallback content.
            
        Returns:
            True if email sent successfully, False otherwise.
        """
        if not self.enabled:
            logger.info(f"[EMAIL] To: {to_email}, Subject: {subject}")
            logger.debug(f"[EMAIL BODY] {html_content[:200]}...")
            return True
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email
            
            # Attach plain text version
            if text_content:
                msg.attach(MIMEText(text_content, 'plain'))
            
            # Attach HTML version
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent to {to_email}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    async def send_account_confirmation(
        self,
        to_email: str,
        username: str,
        role: str
    ) -> bool:
        """Send account approval confirmation email.
        
        Args:
            to_email: User's email address.
            username: Username.
            role: Assigned role.
        """
        subject = "Your Sentinel SOC Account Has Been Approved"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #2563eb;">Welcome to Sentinel SOC!</h2>
            <p>Dear {username},</p>
            <p>Your account has been <strong>approved</strong> by an administrator.</p>
            
            <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0;">Account Details:</h3>
                <ul>
                    <li><strong>Username:</strong> {username}</li>
                    <li><strong>Role:</strong> {role.replace('_', ' ').title()}</li>
                    <li><strong>Status:</strong> Active</li>
                </ul>
            </div>
            
            <p>You can now log in to the Sentinel SOC dashboard using your credentials.</p>
            
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
            <p style="font-size: 12px; color: #6b7280;">
                This is an automated message from Sentinel SOC. Please do not reply to this email.
            </p>
        </body>
        </html>
        """
        
        text_content = f"""
Welcome to Sentinel SOC!

Dear {username},

Your account has been approved by an administrator.

Account Details:
- Username: {username}
- Role: {role.replace('_', ' ').title()}
- Status: Active

You can now log in to the Sentinel SOC dashboard using your credentials.

This is an automated message. Please do not reply.
        """
        
        return await self.send_email(to_email, subject, html_content, text_content)
    
    async def send_alert_assignment_notification(
        self,
        to_email: str,
        username: str,
        alert_id: str,
        alert_classification: str,
        alert_priority: str,
        assigned_by: str,
        is_assigned: bool = True
    ) -> bool:
        """Send alert assignment/unassignment notification.
        
        Args:
            to_email: User's email address.
            username: Username.
            alert_id: Alert identifier.
            alert_classification: Alert classification/title.
            alert_priority: Alert priority level.
            assigned_by: Admin who performed the assignment.
            is_assigned: True if assigned, False if unassigned.
        """
        if is_assigned:
            subject = f"New Alert Assigned: {alert_classification}"
            action = "assigned to you"
            action_past = "Assignment"
        else:
            subject = f"Alert Unassigned: {alert_classification}"
            action = "unassigned from you"
            action_past = "Unassignment"
        
        priority_color = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#2563eb',
            'low': '#16a34a'
        }.get(alert_priority, '#6b7280')
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: {priority_color};">Alert {action_past} Notification</h2>
            <p>Dear {username},</p>
            <p>An alert has been <strong>{action}</strong> by {assigned_by}.</p>
            
            <div style="background: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0;">Alert Details:</h3>
                <ul>
                    <li><strong>Alert ID:</strong> {alert_id}</li>
                    <li><strong>Classification:</strong> {alert_classification}</li>
                    <li><strong>Priority:</strong> 
                        <span style="color: {priority_color}; font-weight: bold;">
                            {alert_priority.upper()}
                        </span>
                    </li>
                </ul>
            </div>
            
            <p>Please log in to the Sentinel SOC dashboard to review and take action.</p>
            
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
            <p style="font-size: 12px; color: #6b7280;">
                This is an automated message from Sentinel SOC. Please do not reply to this email.
            </p>
        </body>
        </html>
        """
        
        text_content = f"""
Alert {action_past} Notification

Dear {username},

An alert has been {action} by {assigned_by}.

Alert Details:
- Alert ID: {alert_id}
- Classification: {alert_classification}
- Priority: {alert_priority.upper()}

Please log in to the Sentinel SOC dashboard to review and take action.

This is an automated message. Please do not reply.
        """
        
        return await self.send_email(to_email, subject, html_content, text_content)

    async def send_password_reset_email(
        self,
        to_email: str,
        username: str,
        reset_link: str
    ) -> bool:
        """Send a password reset email with a secure reset link.
        
        Args:
            to_email: User's email address.
            username: Username for personalisation.
            reset_link: Full URL to the password reset page (includes token).
            
        Returns:
            True if sent (or logged in dev mode), False on error.
        """
        subject = "Sentinel SOC — Password Reset Request"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #2563eb;">Password Reset Request</h2>
            <p>Dear {username},</p>
            <p>We received a request to reset your Sentinel SOC password.</p>

            <div style="margin: 24px 0;">
                <a href="{reset_link}"
                   style="display: inline-block; background: #2563eb; color: #fff;
                          padding: 12px 24px; border-radius: 6px; text-decoration: none;
                          font-weight: bold;">
                    Reset My Password
                </a>
            </div>

            <p style="color: #6b7280; font-size: 13px;">
                This link expires in <strong>1 hour</strong>. If you did not request a password reset,
                you can safely ignore this email — your password will not change.
            </p>

            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;" />
            <p style="font-size: 12px; color: #6b7280;">
                This is an automated message from Sentinel SOC. Please do not reply to this email.
            </p>
        </body>
        </html>
        """
        
        text_content = f"""Password Reset Request

Dear {username},

We received a request to reset your Sentinel SOC password.

Click the link below to reset your password (expires in 1 hour):
{reset_link}

If you did not request a password reset, you can safely ignore this email.

This is an automated message. Please do not reply.
        """
        
        return await self.send_email(to_email, subject, html_content, text_content)


# Global email service instance
email_service = EmailService()
