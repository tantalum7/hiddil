FROM python:2.7
ADD . /hiddil
WORKDIR /hiddil
RUN pip install -r requirements.txt
CMD ["python", "./hiddil/server.py"]
