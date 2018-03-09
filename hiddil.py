
# Library imports
from flask import Flask
from flask.ext.classy import FlaskView, route

# Project imports
from protocol import Protocol


class HiddilServer:

    class HelloView(FlaskView):
        def index(self):
            return "hey buddy"

    class BlockView(FlaskView):

        def get(self):
            return "block-get"

        def put(self):
            return "block-put"

    class SaltView(FlaskView):

        def get(self):
            return "salt-get"

        def put(self):
            return "salt-put"

    class



    def __init__(self):
        self.protocol = Protocol()

        self.app = Flask(__name__)
        self.helloView.register(self.app)

    def run(self):
        self.app.run()



class HiddilClient:

    def __init__(self):
        pass


