FROM python:3.6

WORKDIR /

RUN pip install git+https://github.com/blacklanternsecurity/manspider

ENTRYPOINT ["manspider"]