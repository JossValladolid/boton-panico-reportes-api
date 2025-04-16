# docker container stop boton-panico-reportes-api; docker container rm --force boton-panico-reportes-api; docker image rm --force boton-panico-reportes-api; docker build -t boton-panico-reportes-api .; docker run -p 8000:80 --name boton-panico-reportes-api boton-panico-reportes-api

FROM python:3.10-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
