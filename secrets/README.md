## Secrets

These files are read by Docker Compose as secrets and mounted at `/run/secrets/` inside containers. They are **never committed to git**.

### Setup

Create each file with your credentials (one value per file, no trailing newline):

```bash
echo -n "your-email@gmail.com" > secrets/gmail_user.txt
echo -n "xxxx-xxxx-xxxx-xxxx" > secrets/gmail_app_password.txt
echo -n "recipient@gmail.com" > secrets/alert_recipient.txt
chmod 600 secrets/gmail_*.txt secrets/alert_*.txt
```

### Getting a Gmail App Password

1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and your device
3. Copy the 16-character password (spaces don't matter)
