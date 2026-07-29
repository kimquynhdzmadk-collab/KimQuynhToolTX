"""MD5 TAI/XIU API - 85 deterministic algorithms"""
import math,time,os,json
from flask import Flask,request,jsonify
from flask_cors import CORS
from collections import Counter

app=Flask(__name__);CORS(app);ST=time.time()
def h2b(h):return[int(h[i:i+2],16)for i in range(0,32,2)\