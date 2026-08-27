FROM quay.io/sclorg/python-312-c9s:latest

USER 0
WORKDIR /app

COPY requirements.txt .
RUN python3.12 -m pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R 1001:0 /app

USER 1001
EXPOSE 8000

CMD ["python3.12", "manage.py", "runserver", "0.0.0.0:8000"]
