#from flask import Flask, flash, abort, redirect, url_for, request, render_template, make_response, json, Response
from flask import Flask, redirect, url_for, render_template, make_response
#import os
#import sys
import config
import boto.ec2.elb
import boto
from boto.ec2 import *
import boto.vpc
import boto.rds
import datetime
from datetime import datetime, timedelta
import redis
import pickle
import ast

app = Flask(__name__)

class AWSDash(object):
    """Helper methods for AWS access"""
    def __init__(self, aws_key, aws_secret, redis_host=None, redis_port=None):
        super(AWSDash, self).__init__()
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.timeout = 3000
        self.conn = None
        self.vpcconn = None
        self.elbconn = None
        self.rdsconn = None

        if redis_host and redis_port:
            self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=0)
        else:
            exit("Redis cache server not configured.")

    def get_conn(self, region):
        self.conn = connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_vpc_conn(self, region):
        self.vpcconn = boto.vpc.connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_elb_conn(self, region):
        self.elbconn = boto.ec2.elb.connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_rds_conn(self, region):
        self.rdsconn = boto.rds.connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_zones(self, region):
        key = "zones/%s" % region
        if not self.redis.exists(key):
            self.get_conn(region)
            self.redis.set(key, pickle.dumps(self.conn.get_all_zones()))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    ## TODO: Unpack values from SG object and add them to redis as strings.
    def get_sec_groups(self, region, group_id):
        if group_id:
            group_ids = [group_id]
        else:
            group_ids = None

        self.get_conn(region)
        return self.conn.get_all_security_groups(group_ids=group_ids)

    def get_instances(self, region):
        key = "instances/%s" % region
        if not self.redis.exists(key):
            self.get_conn(region)
            self.redis.set(key, pickle.dumps(self.conn.get_all_instance_status(max_results=2000)))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_instance_info(self, region, instance_id):
        key = "instance/%s/%s" % (region, instance_id)
        if not self.redis.exists(key):
            self.get_conn(region)
            instance = self.conn.get_all_instances([instance_id])[0].instances[0]
            inst = {
                'instance_name': instance.tags['Name'],
                'instance_type': instance.instance_type,
                'instance_ami': instance.image_id,
                'instance_private_ip': instance.private_ip_address,
                'instance_public_ip': instance.ip_address,
                'instance_dns_name': instance.dns_name,
                'instance_vpc': instance.vpc_id,
                'instance_sg': instance.groups[0].id,
                'instance_key': instance.key_name,
                'instance_tags': flatten_tags(instance.tags)
            }
            self.redis.set(key, pickle.dumps(inst))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_ebs(self, region):
        key = "ebs/%s" % region
        if not self.redis.exists(key):
            self.get_conn(region)
            self.redis.set(key, pickle.dumps(self.conn.get_all_volumes()))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_addresses(self, region):
        key = "addrs/%s" % region
        if not self.redis.exists(key):
            self.get_conn(region)
            self.redis.set(key, pickle.dumps(self.conn.get_all_addresses()))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_subnets(self, region, vpcid=None):
        if vpcid:
            key = "subnets/%s/%s" % (region, vpcid)
            filter = {'vpcId': [vpcid]}
        else:
            key = "subnets/%s" % region
            filter = None
        if not self.redis.exists(key):
            self.get_vpc_conn(region)
            self.redis.set(key, pickle.dumps(self.vpcconn.get_all_subnets(filters=filter)))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_vpcs(self, region):
        self.get_vpc_conn(region)
        return self.vpcconn.get_all_vpcs()

    def get_loadbalancers(self, region):
        key = "elb/%s" % region
        if not self.redis.exists(key):
            self.get_elb_conn(region)
            self.redis.set(key, pickle.dumps(self.elbconn.get_all_load_balancers()))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

    def get_rds(self, region):
        key = "rds/%s" % region
        if not self.redis.exists(key):
            self.get_rds_conn(region)
            self.redis.set(key, pickle.dumps(self.rdsconn.get_all_dbinstances()))
            self.redis.expire(key, self.timeout)

        return pickle.loads(self.redis.get(key))

def flatten_tags(tags):
    return ', '.join("%s=%r" % (key,str(val)) for (key,val) in tags.iteritems())

def parse_endpoint(endpoint):
    return "mysql://%s:%d" % (str(endpoint[0]), endpoint[1])

def clean_up_sg_rules(rules):
    a = []
    for rule in rules:
        a.append(str(rule).replace('IPPermissions:', ""))
    return a

def get_sg_from_rds(sg):
    if sg:
        return str(sg).split(':')[1].strip(']')
    else:
        return None

creds = config.ec2_conf()
aws = AWSDash(creds['AWS_ACCESS_KEY_ID'], creds['AWS_SECRET_ACCESS_KEY'], config.redis_host(), config.redis_port())

@app.route('/')
def index():
    list = []

    for region in config.region_list():
        zones = aws.get_zones(region)
        instances = aws.get_instances(region)
        ebs = aws.get_ebs(region)
        subnets = aws.get_subnets(region)
        vpcs = aws.get_vpcs(region)
        rds = aws.get_rds(region)

        unattached_ebs = 0
        unattached_eli = 0
        event_count = 0
        improperelb = 0
        ip_low_subnet = 0

        for subnet in subnets:
            if subnet.available_ip_address_count < 15:
                ip_low_subnet = ip_low_subnet + 1

        for instance in instances:
            events = instance.events
            if events and "Completed" not in instance.events[0].description:
                event_count = event_count + 1

        for vol in ebs:
            state = vol.attachment_state()
            if state == None:
                try:
                    vol.tags['Status']
                    if vol.tags['Status'] == "InUse":
                        continue
                except KeyError:
                    unattached_ebs = unattached_ebs + 1

        elis = aws.get_addresses(region)
        for eli in elis:
            instance_id = eli.instance_id
            if not instance_id:
                unattached_eli = unattached_eli + 1

        elbs = aws.get_loadbalancers(region)
        for elb in elbs:
            if len(elb.instances) < 1:
                improperelb = improperelb + 1
        list.append({ 'region' : region, 'zones': zones, 'instance_count' : len(instances), 'ebscount' : len(ebs),
            'unattached_ebs' : unattached_ebs, 'eli_count' : len(elis), 'unattached_eli' : unattached_eli,
            'elb_count' : len(elbs), 'event_count' : event_count, 'improper_elb': improperelb,
            'subnet_counter': len(subnets), 'ip_low_subnet': ip_low_subnet, 'vpc_count': len(vpcs), 'rds_counter': len(rds)})
    return render_template('index.html', list=list)


@app.route('/ec2/ebs/volumes/<region>/')
def ebs_volumes(region=None):
    ebs = aws.get_ebs(region)
    ebs_vol = []
    for vol in ebs:
        state = vol.attachment_state()
        ebs_info = { 'id': vol.id, 'size': vol.size, 'iops': vol.iops, 'status': vol.status,
        'create_time': vol.create_time , 'tags': flatten_tags(vol.tags), 'type': vol.type,
        'snapshot_id': vol.snapshot_id, 'vol_state': state}
        ebs_vol.append(ebs_info)
    return render_template('ebs_volume.html', ebs_vol=ebs_vol, region=region)


@app.route('/ec2/eips/<region>/')
def elastic_ips(region=None):
    elis = aws.get_addresses(region)
    un_eli = []
    for eli in elis:
        instance_id = eli.instance_id
        if not instance_id:
            eli_info = {'public_ip': eli.public_ip, 'domain': eli.domain}
            un_eli.append(eli_info)
    return render_template('elastic_ip.html', un_eli=un_eli, region=region)


@app.route('/elb/<region>/')
def elbimproper(region=None):
    elbs = aws.get_loadbalancers(region)
    elb_list = []
    for elb in elbs:
        elb_info = {
            'elb_name': elb.dns_name,
            'elb_attached_instances': elb.instances,
            'elb_healthcheck': elb.health_check
        }
        elb_list.append(elb_info)
    return render_template('elb.html', elb_list=elb_list)


@app.route('/ec2/events/<region>/')
def instance_events(region=None):
    instances = aws.get_instances(region)
    instance_event_list = []
    for instance in instances:
        event = instance.events
        if event:
            instance_name = aws.get_instance_info([instance.id])
            event_info = { 'instance_id' : instance.id, 'instance_name' : instance_name[0].instances[0].tags['Name'],
            'event' : instance.events[0].code, 'description' : instance.events[0].description,
            'event_before' : instance.events[0].not_before, 'event_after': instance.events[0].not_after }
            instance_event_list.append(event_info)
    return render_template('instance_events.html', instance_event_list=instance_event_list)

@app.route('/ec2/sec_groups/<region>/<group_id>')
def security_groups(region=None, group_id=None):
    sgs = aws.get_sec_groups(region, group_id)
    sg_list = []
    for sg in sgs:
        sg_info ={
            'sg_name': sg.name,
            'sg_id': sg.id,
            'sg_desc': sg.description,
            'sg_vpc': sg.vpc_id,
            'sg_region': sg.region,
            'sg_rules': clean_up_sg_rules(sg.rules)
        }
        sg_list.append(sg_info)
    return render_template('sg_info.html', sg_list=sg_list)

@app.route('/ec2/instances/<region>/<vpcid>')
@app.route('/ec2/instances/<region>/', defaults={'vpcid': None})
def instances_list(region=None, vpcid=None):
    instances = aws.get_instances(region)
    instance_list = []
    for instance in instances:
        inst = aws.get_instance_info(region, instance.id)

        ## If we pass vpc-id here we want only instances from a given vpc.
        if vpcid and vpcid != inst['instance_vpc']:
            continue

        instance_info = {
            'instance_region': region,
            'instance_id': instance.id,
            'instance_state': instance.state_name,
            'instance_zone': instance.zone,
            'instance_name': inst['instance_name'],
            'instance_type': inst['instance_type'],
            'instance_ami': inst['instance_ami'],
            'instance_private_ip': inst['instance_private_ip'],
            'instance_public_ip': inst['instance_public_ip'],
            'instance_dns_name': inst['instance_dns_name'],
            'instance_vpc': inst['instance_vpc'],
            'instance_sg': inst['instance_sg'],
            'instance_key': inst['instance_key'],
            'instance_tags': inst['instance_tags']
        }
        instance_list.append(instance_info)
    return render_template('instances.html', instance_list=instance_list)


@app.route('/vpc/subnet/<region>/<vpcid>')
@app.route('/vpc/subnet/<region>/', defaults={'vpcid': None})
def subnet_info(region=None, vpcid=None):
    subnets = aws.get_subnets(region, vpcid)
    vpc_subnets = []
    for subnet in subnets:
        subnet_info = {
            'subnet_id': subnet.id,
            'subnet_vpc': subnet.vpc_id,
            'subnet_state': subnet.state,
            'subnet_cidr': subnet.cidr_block,
            'subnet_az': subnet.availability_zone,
            'subnet_avail_ip': subnet.available_ip_address_count,
            'subnet_tags': flatten_tags(subnet.tags)
        }
        vpc_subnets.append(subnet_info)
    return render_template('subnet.html', vpc_subnets=vpc_subnets)


@app.route('/vpc/list/<region>/')
def vpc_list(region=None):
    vpcs = aws.get_vpcs(region)
    vpc_list = []
    for vpc in vpcs:
        vpc_info = {
            'vpc_region': region,
            'vpc_id': vpc.id,
            'vpc_state': vpc.state,
            'vpc_cidr': vpc.cidr_block,
            'vpc_dhcp': vpc.dhcp_options_id
        }
        vpc_list.append(vpc_info)
    return render_template('vpcs.html', vpcs=vpc_list)

@app.route('/rds/list/<region>')
def rds_list(region=None):
    rds = aws.get_rds(region)
    rds_list = []
    for db in rds:
        rds_info = {
            'rds_region': region,
            'rds_id': db.id,
            'rds_engine': db.engine,
            'rds_status': db.status,
            'rds_storage': db.allocated_storage,
            'rds_endpoint': parse_endpoint(db.endpoint),
            'rds_user': db.master_username,
            'rds_last_backup': db.latest_restorable_time,
            'rds_az': db.availability_zone,
            'rds_multi_az': db.multi_az,
            'rds_sg': get_sg_from_rds(db.vpc_security_groups)
        }
        rds_list.append(rds_info)
    return render_template('rds.html', rds=rds_list)


if __name__ == '__main__':
    app.debug = config.app_debug()
    app.run(host=config.listen_host(), port=config.listen_port())
