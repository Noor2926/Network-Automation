# modules/email.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import requests
import json

# Configure logging
logger = logging.getLogger("email_module")

# SMTP Configuration
SMTP_HOST = 'smtp.hostinger.com'
SMTP_PORT = 465
SMTP_USER = 'gyanfit@nutrinexas.com'
SMTP_PASS = 'm&VL1Lo4'

# BIR SMS API Configuration
SMS_API_KEY = '3B853539856F3FD36823E959EF82ABF6'
SMS_API_URL = 'https://user.birasms.com/api/smsapi'
SMS_ROUTE_ID = 'SI_Alert'

def send_email(recipient, subject, message):
    """
    Send an email to the specified recipient.
    
    Args:
        recipient (str): Email address of the recipient
        subject (str): Email subject
        message (str): Email body
    
    Returns:
        dict: Status and message of the email sending operation
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = recipient
        msg['Subject'] = subject
        
        # Add message body
        msg.attach(MIMEText(message, 'plain'))
        
        # Connect to SMTP server
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, recipient, msg.as_string())
        
        logger.info(f"Email sent successfully to {recipient}")
        return {
            "status": "success",
            "message": f"Email sent to {recipient}"
        }
    
    except Exception as e:
        logger.error(f"Error sending email to {recipient}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to send email: {str(e)}"
        }

def send_sms(phone_numbers, message):
    """
    Send an SMS to the specified phone numbers using BIR SMS API.
    
    Args:
        phone_numbers (str): Comma-separated phone numbers
        message (str): SMS message content
    
    Returns:
        dict: Status and message of the SMS sending operation
    """
    try:
        # Clean phone numbers (remove spaces, dashes, etc.)
        phone_numbers = ''.join(filter(str.isdigit, phone_numbers))
        
        # Prepare POST parameters
        post_data = {
            'key': SMS_API_KEY,
            'campaign': 'Default',
            'routeid': SMS_ROUTE_ID,
            'type': 'text',
            'contacts': phone_numbers,
            'msg': message,
            'responsetype': 'json'
        }
        
        # Send POST request
        response = requests.post(SMS_API_URL, data=post_data, verify=False)
        response_data = response.json()
        
        if response_data.get('response', {}).get('code') == '200':
            logger.info(f"SMS sent successfully to {phone_numbers}")
            return {
                "status": "success",
                "message": f"SMS sent to {phone_numbers}",
                "response": response_data
            }
        else:
            logger.error(f"Failed to send SMS: {response_data}")
            return {
                "status": "error",
                "message": f"Failed to send SMS: {response_data.get('response', {}).get('msg', 'Unknown error')}",
                "response": response_data
            }
    
    except Exception as e:
        logger.error(f"Error sending SMS to {phone_numbers}: {str(e)}")
        return {
            "status": "error",
            "message": f"Failed to send SMS: {str(e)}"
        }
        