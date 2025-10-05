FROM python:3

WORKDIR /root/

RUN apt-get update -y
RUN apt-get upgrade -y

RUN apt-get install nano golang-go python3-pip -y

RUN git clone https://github.com/gitleaks/gitleaks.git
RUN cd gitleaks;make build

RUN mkdir scanApp

COPY scanApi.py scanApp/.
COPY config.txt scanApp/.

RUN pip3 install Flask
RUN pip3 install jsonify

ENV PATH=/root/gitleaks/:${PATH}

WORKDIR /root/scanApp/

ENTRYPOINT ["python"]

CMD ["scanApi.py"]
