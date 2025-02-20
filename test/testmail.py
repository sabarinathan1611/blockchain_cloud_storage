import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

smtp_server = "188.245.68.247"  # Correct SMTP server
smtp_port = 587
email_address = "2021pecit303_sabarinathan@panimalar.ac.in"
email_password = "#Sabarinathan7"
recipient = "vsabarinathan1611@gmail.com"

subject = "Test Email from Python"
body = "Hello, this is a test email sent from my domain mail using Python."


# Create email message
message = MIMEMultipart()
message["From"] = email_address
message["To"] = recipient
message["Subject"] = subject
message.attach(MIMEText(body, "plain"))

try:
    # Connect to SMTP server
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.set_debuglevel(1)  # Enable debug output
    server.starttls()  # Start TLS encryption
    server.login(email_address, email_password)  # Login
    server.send_message(message)  # Send email
    print("Email sent successfully!")
except smtplib.SMTPAuthenticationError as auth_err:
    print(f"Authentication failed: {auth_err}")
except Exception as e:
    print(f"Failed to send email: {e}")
finally:
    server.quit()

