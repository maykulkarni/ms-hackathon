from flask import Flask
from pymongo import MongoClient
app = Flask(__name__)

@app.route('/')
def hello_world():
  client = MongoClient("localhost", 27017)
  return 'Hello, World! I am a pro coder \n #DevOps'

if __name__ == '__main__':
  app.run()
