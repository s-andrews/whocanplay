#!/usr/bin/env python3

from flask import Flask, request, render_template, make_response, redirect, url_for
import random
from urllib.parse import quote_plus
from pymongo import MongoClient
from bson.json_util import dumps
from pathlib import Path
import json
import time
import datetime


app = Flask(__name__)


@app.route("/")
def index():


    return render_template(
        "index.html",
    )



@app.route("/login", methods = ['POST', 'GET'])
def process_login():
    """
    Validates an email / password combination and generates
    a session id to authenticate them in future

    @email:  Their email
    @password:  The unhashed version of their password

    @returns:   Forwards the session code to the json response
    """
    form = get_form()
    email = form["email"]
    password = form["password"]

    # We might not try the authentication for a couple of reasons
    # 
    # 1. We might have blocked this IP for too many failed logins
    # 2. We might have locked this account for too many failed logins

    # Calculate when any timeout ban would have to have started so that
    # it's expired now
    timeout_time = int(time.time())-(60*(int(server_conf["security"]["lockout_time_mins"])))


    # We'll check the IP first
    ip = ips.find_one({"ip":request.remote_addr})
    
    if ip and len(ip["failed_logins"])>=server_conf["security"]["failed_logins_per_ip"]:
        # Find if they've served the timeout
        last_time = ip["failed_logins"][-1]

        if last_time < timeout_time:
            # They've served their time so remove the records of failures
            ips.update_one({"ip":request.remote_addr},{"$set":{"failed_logins":[]}})

        else:
            raise Exception("IP block timeout")

    # See if we have a record of failed logins for this user
    person = people.find_one({"email":email})

    if person and person["locked_at"]:
        if person["locked_at"] > timeout_time:
            # Their account is locked
            raise Exception("User account locked")
        else:
            # They've served their time, so remove the lock
            # and failed logins
            people.update_one({"email":email},{"$set":{"locked_at":0}})
            people.update_one({"email":email},{"$set":{"failed_logins":[]}})


    # Check the password
    try:    
        ## TODO: Check the password, raise an exception if it's wrong.

        # Clear any IP recorded login fails
        ips.delete_one({"ip":request.remote_addr})

        sessioncode = generate_id(20)

        # We can assign the new sessioncode to them and then set a cookie with it in 
        people.update_one({"email":email},{"$set":{"sessioncode": sessioncode}})

        # TODO Set Cookie
        return(sessioncode)
    
    except Exception as e:
        # We need to record this failure.  If there is a user with this name we record
        # against that.  If not then we just record against the IP
        people.update_one({"email":email},{"$push":{"failed_logins":int(time.time())}})
        if len(person["failed_logins"])+1 >= server_conf["security"]["failed_logins_per_user"]:
            # We need to lock their account
            people.update_one({"email":email},{"$set":{"locked_at":int(time.time())}})
                


        if not ip:
            ips.insert_one({"ip":request.remote_addr,"failed_logins":[]})

        ips.update_one({"ip":request.remote_addr},{"$push":{"failed_logins":int(time.time())}})

        raise Exception("Incorrect Email/Password")

def get_form():
    # In addition to the main arguments we also add the session
    # string from the cookie
    session = ""

    if "whocanplay_session_id" in request.cookies:
        session = request.cookies["whocanplay_session_id"]

    if request.method == "GET":
        form = request.args.to_dict(flat=True)
        form["session"] = session
        return form

    elif request.method == "POST":
        form = request.form.to_dict(flat=True)
        form["session"] = session
        return form


def generate_id(size):
    """
    Generic function used for creating IDs.  Makes random IDs
    just using uppercase letters

    @size:    The length of ID to generate

    @returns: A random ID of the requested size
    """
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    code = ""

    for _ in range(size):
        code += random.choice(letters)

    return code


def checksession (sessioncode):
    """
    Validates a session code and retrieves a person document

    @sessioncode : The session code from the browser cookie

    @returns:      The document for the person associated with this session
    """

    person = people.find_one({"sessioncode":sessioncode})

    if "disabled" in person and person["disabled"]:
        raise Exception("Account disabled")

    if person:
        return person

    raise Exception("Couldn't validate session")



def jsonify(data):
    # This is a function which deals with the bson structures
    # specifically ObjectID which can't auto convert to json 
    # and will make a flask response object from it.
    response = make_response(dumps(data))
    response.content_type = 'application/json'

    return response

def get_server_configuration():
    with open(Path(__file__).resolve().parent.parent / "configuration/conf.json") as infh:
        conf = json.loads(infh.read())
    return conf


def connect_to_database(conf):

    client = MongoClient(
        conf['server']['address'],
        username = conf['server']['username'],
        password = conf['server']['password'],
        authSource = "whocanplay_database"
    )


    db = client.capstone_database

    global people
    people = db.people_collection

    global ips
    ips = db.ips_collection




# Read the main configuration
server_conf = get_server_configuration()

# Connect to the database
connect_to_database(server_conf)


