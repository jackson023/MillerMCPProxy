FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py smart_pool.py work_ticket.py culprit.py line_trace.py arg_parse.py .
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
