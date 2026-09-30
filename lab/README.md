# CASA Vulnerable Lab

A deliberately misconfigured FastAPI app used as the local, authorized test
target. It is for development and demos only — never expose it to any network
you do not own.

## Run standalone

```bash
pip install fastapi uvicorn
python -m lab.vulnerable_app
```

It listens on `http://127.0.0.1:8001`.

## What it exposes (on purpose)

| Issue | Endpoint |
| --- | --- |
| Missing security headers | all responses |
| Insecure session cookie | `/login` |
| robots.txt disclosing sensitive paths | `/robots.txt` |
| Fake secrets file | `/.env` |
| Git metadata | `/.git/HEAD` |
| Directory listing | `/files` |
| Tech signature (jQuery script tag) | `/` |

## Docker

```bash
docker compose up --build lab
```
