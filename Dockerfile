FROM python:3.6-slim-buster

LABEL maintainer="tinhhn.uit@gmail.com"

WORKDIR /app

COPY trigger.py .

RUN pip3 install python_gitlab \
    && echo "alias trigger='python /app/trigger.py'" >> ~/.bashrc
