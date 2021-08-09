FROM python:3.6-slim-buster

LABEL maintainer="tinhhn.uit@gmail.com"

WORKDIR /app

COPY trigger.py /usr/local/bin/trigger

RUN pip3 install python_gitlab \
    && chmod +x /usr/local/bin/trigger
