# mini-xdr — 워커·콘솔 공용 이미지
# 비밀값(.env)은 이미지에 넣지 않고 실행 때 env_file 로 받는다(.dockerignore 로도 이중 차단).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY sql/ sql/

# 루트가 아닌 사용자로 실행
RUN useradd --create-home --uid 10001 xdr
USER xdr

CMD ["python", "-m", "app.worker"]
