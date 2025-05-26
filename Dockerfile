FROM python:3.7

RUN apt-get update && apt-get install -y krb5-user

COPY . /manspider
WORKDIR /manspider

RUN pip install .

ENTRYPOINT ["manspider"]