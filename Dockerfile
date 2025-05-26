FROM python:3.10

RUN apt-get update && apt-get install -y krb5-user tesseract-ocr antiword

COPY . /manspider
WORKDIR /manspider

RUN pip install .

ENTRYPOINT ["manspider"]