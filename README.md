# Hiddil

## Setup

### Dockerisd

Ensure you have docker and docker-compose installed

https://docs.docker.com/engine/installation/

https://docs.docker.com/compose/install/

`docker-compose build` wiull build the containers.

`docker-compose up` will run them.


#### Running the client

Follow the instructions below for a venv'ed enviroment and use the instructions to run the client.

### VirtualEnv

#### Install venv

https://virtualenv.pypa.io/en/stable/installation/

#### Make a venv

Python 3~ `python3 -m venv venv`

Python2.7~ `virtualenv venv`

#### Activate & Install requirements

`source venv/bin/activate`

`cd hiddil`

`pip install -r requirements.txt`

## Run

### Server 

`python server.py` or `./server.py`

### Client 

`python client.py` or `./client.py`