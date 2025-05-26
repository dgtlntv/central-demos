FROM python:3.13-slim

WORKDIR /app

# Copy project files
COPY pyproject.toml main.py ./

# Install project and dependencies using pip
RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]