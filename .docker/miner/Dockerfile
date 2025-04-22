FROM python:3.11-slim

RUN mkdir /app

WORKDIR /app

RUN python -c "import urllib.request; urllib.request.urlretrieve('https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/blob/main/Llama-3.2-3B-Instruct-Q6_K_L.gguf', '/app/Llama-3.2-3B-Instruct-Q6_K_L.gguf')"

RUN apt-get update && apt-get install build-essential git -y

COPY requirements.version.txt .
COPY requirements.txt .

RUN pip install llama-cpp-python setuptools --upgrade
RUN pip install -r requirements.txt
COPY . /app

RUN pip install -e .