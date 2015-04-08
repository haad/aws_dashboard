#!/usr/bin/python
# vim: set expandtab:
import os
def ec2_conf():
    return {'AWS_ACCESS_KEY_ID' : os.environ.get('AWS_ACCESS_KEY_ID'), 'AWS_SECRET_ACCESS_KEY' : os.environ.get('AWS_SECRET_ACCESS_KEY')}

def region_list():
    region_list = ['us-east-1','us-west-1','us-west-2']
    return region_list

def app_debug():
    debug = True
    return debug

def listen_port():
    port = 5050
    return port

def listen_host():
    host = 'localhost'
    return host

def redis_host():
    redis_host = 'localhost'
    return redis_host

def redis_port():
    redis_port = 6379
    return redis_port
