FROM python:3.12-slim

RUN addgroup --system aikms && adduser --system --ingroup aikms aikms
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

USER aikms

EXPOSE 8086

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8086"]
