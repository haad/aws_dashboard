#from flask import Flask, flash, abort, redirect, url_for, request, render_template, make_response, json, Response
from flask import Flask, redirect, url_for, render_template, make_response
#import os
#import sys
import config
import boto.ec2.elb
import boto
from boto.ec2 import *
import boto.vpc


app = Flask(__name__)


@app.route('/')
def index():

    list = []
    creds = config.get_ec2_conf()
    key = creds['AWS_ACCESS_KEY_ID']
    secret = creds['AWS_SECRET_ACCESS_KEY']

    for region in config.region_list():
        conn = connect_to_region(region, aws_access_key_id=key, aws_secret_access_key=secret)
        vpcconn = boto.vpc.connect_to_region(region, aws_access_key_id=key, aws_secret_access_key=secret)
        zones = conn.get_all_zones()
        instances = conn.get_all_instance_status(max_results=2000)
        instance_count = len(instances)
        ebs = conn.get_all_volumes()
        ebscount = len(ebs)
        subnets = vpcconn.get_all_subnets()
        unattached_ebs = 0
        unattached_eli = 0
        event_count = 0
        improperelb = 0
        subnet_counter = 0
        ip_low_subnet = 0
        subnet_counter = len(subnets)

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


        elis = conn.get_all_addresses()
        eli_count = len(elis)

        for eli in elis:
            instance_id = eli.instance_id
            if not instance_id:
                unattached_eli = unattached_eli + 1

        connelb = boto.ec2.elb.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
        elbs = connelb.get_all_load_balancers()
        elb_count = len(elbs)

        for elb in elbs:
            if len(elb.instances) < 1:
                improperelb = improperelb + 1
        list.append({ 'region' : region, 'zones': zones, 'instance_count' : instance_count, 'ebscount' : ebscount, 'unattached_ebs' : unattached_ebs, 'eli_count' : eli_count, 'unattached_eli' : unattached_eli, 'elb_count' : elb_count, 'event_count' : event_count, 'improper_elb': improperelb, 'subnet_counter': subnet_counter, 'ip_low_subnet': ip_low_subnet})

    return render_template('index.html', list=list)


@app.route('/ebs_volumes/<region>/')
def ebs_volumes(region=None):
    creds = config.get_ec2_conf()
    conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    ebs = conn.get_all_volumes()
    ebs_vol = []
    for vol in ebs:
        state = vol.attachment_state()
        if state == None:
            ebs_info = { 'id' : vol.id, 'size' : vol.size, 'iops' : vol.iops, 'status' : vol.status, 'create_time' : vol.create_time , 'tags' : vol.tags}
            ebs_vol.append(ebs_info)
    return render_template('ebs_volume.html', ebs_vol=ebs_vol, region=region)


@app.route('/ebs_volumes/<region>/delete/<vol_id>')
def delete_ebs_vol(region=None, vol_id=None):
    creds = config.get_ec2_conf()
    conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    vol_id = vol_id.encode('ascii')
    vol_ids = conn.get_all_volumes(volume_ids=vol_id)
    for vol in vol_ids:
        vol.delete()
    return redirect(url_for('ebs_volumes', region=region))


@app.route('/elastic_ips/<region>/')
def elastic_ips(region=None):
    creds = config.get_ec2_conf()
    conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    elis = conn.get_all_addresses()
    un_eli = []
    for eli in elis:
        instance_id = eli.instance_id
        if not instance_id:
            eli_info = {'public_ip': eli.public_ip, 'domain': eli.domain}
            un_eli.append(eli_info)
    return render_template('elastic_ip.html', un_eli=un_eli, region=region)


@app.route('/elastic_ips/<region>/delete/<ip>')
def delete_elastic_ip(region=None, ip=None):
    creds = config.get_ec2_conf()
    conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    ip = ip.encode('ascii')
    elis = conn.get_all_addresses(addresses=ip)

    for eli in elis:
        eli.release()
    return redirect(url_for('elastic_ips', region=region))


@app.route('/instance_events/<region>/')
def instance_events(region=None):
    creds = config.get_ec2_conf()
    conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    instances = conn.get_all_instance_status()
    instance_event_list = []
    for instance in instances:
        event = instance.events
        if event and "Completed" not in instance.events[0].description:
            instance_name = conn.get_all_instances([instance.id])
            event_info = { 'instance_id' : instance.id, 'instance_name' : instance_name[0].instances[0].tags['Name'], 'event' : instance.events[0].code, 'description' : instance.events[0].description, 'event_before' : instance.events[0].not_before, 'event_after': instance.events[0].not_after }
            instance_event_list.append(event_info)
    return render_template('instance_events.html', instance_event_list=instance_event_list)


@app.route('/elbimproper/<region>/')
def elbimproper(region=None):
    creds = config.get_ec2_conf()
    connelb = boto.ec2.elb.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    elbs = connelb.get_all_load_balancers()
    badelb = []
    for elb in elbs:
        if len(elb.instances) < 1:
            elb_info = {'elb_name': elb.dns_name, 'elb_attached_instances': elb.instances, 'elb_healthcheck': elb.health_check}
            badelb.append(elb_info)
    return render_template('elb.html', badelb=badelb)

@app.route('/lowipsubnet/<region>/')
def lowipsubnet(region=None):
    creds = config.get_ec2_conf()
    vpcconn = boto.vpc.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
    subnets = vpcconn.get_all_subnets()
    lowsubnet = []
    for subnet in subnets:
        if subnet.available_ip_address_count < 15:
            subnet_info = {'subnet_id': subnet.id, 'subnet_cidr': subnet.cidr_block, 'subnet_az': subnet.availability_zone, 'subnet_avail_ip': subnet.available_ip_address_count, 'subnet_tags': subnet.tags}
            lowsubnet.append(subnet_info)
    return render_template('subnet.html', lowsubnet=lowsubnet)


if __name__ == '__main__':
    app.debug = True
    app.run(host='127.0.0.1')
