FROM python:3.11-slim

RUN apt-get update && apt-get install -y git curl
WORKDIR /app

COPY requirements.version.txt .
COPY requirements.txt .
RUN pip install bittensor-cli
RUN pip install -r requirements.txt 
COPY . /app
RUN pip install -e .

CMD [ "./scripts/run_in_docker.sh" ]