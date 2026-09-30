FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /lab

RUN pip install --no-cache-dir fastapi uvicorn

COPY vulnerable_app.py .

ENV LAB_HOST=0.0.0.0 LAB_PORT=8001

EXPOSE 8001
CMD ["python", "vulnerable_app.py"]
