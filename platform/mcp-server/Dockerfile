FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY schemas/ schemas/
COPY tools/ tools/
COPY sample_data/ sample_data/

CMD ["python", "main.py", "--help"]
