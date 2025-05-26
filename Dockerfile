FROM python:3.7

COPY . /manspider
WORKDIR /manspider

RUN pip install .

ENTRYPOINT ["manspider"]