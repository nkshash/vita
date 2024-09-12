from flask import Flask
from flask_pymongo import PyMongo
from pymongo import MongoClient

def create_app():
    app = Flask(__name__)
    app.config["MONGO_URI"] = "mongodb://localhost:27017/user_database"
    app.secret_key = 'your_secret_key'  # Necessary for session management

    # MongoDB connection
    client = MongoClient("mongodb://localhost:27017/")
    db = client['user_database']
    users_collection = db['users']

    mongo = PyMongo(app)
    return app, mongo, users_collection
