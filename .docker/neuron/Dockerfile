FROM python:3.11-slim

RUN apt-get update && apt-get install -y git libcurl4
WORKDIR /app

COPY requirements.version.txt .

COPY requirements.txt .
RUN pip install setuptools --upgrade

RUN pip install -r requirements.txt

COPY . /app