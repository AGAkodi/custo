FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --from=frontend /build/dist /app/web
RUN useradd --create-home --uid 10001 custos
USER custos
CMD ["sh", "-c", "exec uvicorn app.hosted:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
