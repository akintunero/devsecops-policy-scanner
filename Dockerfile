FROM python:3.9
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5001
CMD ["python3", "src/webhook.py"]
