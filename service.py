#from flask import Flask, flash, abort, redirect, url_for, request, render_template, make_response, json, Response
from flask import Flask, redirect, url_for, render_template, make_response
#import os
#import sys
import config
import boto.ec2.elb
import boto
from boto.ec2 import *
import boto.vpc
import datetime
from datetime import datetime, timedelta

app = Flask(__name__)

class AWSDash(object):
    """Helper methods for AWS access"""
    def __init__(self, aws_key, aws_secret):
        super(AWSDash, self).__init__()
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.timeout = 300
        self.conn = None
        self.vpcconn = None
        self.elbconn = None
        self.zones = {}
        self.instances = {}
        self.ebs = {}
        self.subnets = {}
        self.loadbs = {}
        self.addrs = {}

    def get_time_diff(self, start_time):
        (start_time - datetime.now()).total_seconds()

    def get_conn(self, region):
        self.conn = connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_vpc_conn(self, region):
        self.vpcconn = boto.vpc.connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_elb_conn(self, region):
        self.elbconn = boto.ec2.elb.connect_to_region(region, aws_access_key_id=self.aws_key,
            aws_secret_access_key=self.aws_secret)

    def get_zones(self, region):
        if region not in self.zones or self.get_time_diff(self.zones[region]['time']) > self.timeout:
            self.get_conn(region)
            self.zones[region] = {}
            self.zones[region]['res'] = self.conn.get_all_zones()
            self.zones[region]['time'] = datetime.now()
        return self.zones[region]['res']

    def get_instances(self, region):
        if region not in self.instances or self.get_time_diff(self.instances[region]['time']) > self.timeout:
            self.get_conn(region)
            self.instances[region] = {}
            self.instances[region]['res'] = self.conn.get_all_instance_status(max_results=2000)
            self.instances[region]['time'] = datetime.now()
        return self.instances[region]['res']

    def get_instance_info(self, region, instance_id):
        self.get_conn(region)
        return self.conn.get_all_instances([instance_id])

    def get_ebs(self, region):
        if region not in self.ebs or self.get_time_diff(self.ebs[region]['time']) > self.timeout:
            self.get_conn(region)
            self.ebs[region] = {}
            self.ebs[region]['res'] = self.conn.get_all_volumes()
            self.ebs[region]['time'] = datetime.now()
        return self.ebs[region]['res']

    def get_addresses(self, region):
        if region not in self.addrs or self.get_time_diff(self.addrs[region]['time']) > self.timeout:
            self.get_conn(region)
            self.addrs[region] = {}
            self.addrs[region]['res'] = self.conn.get_all_addresses()
            self.addrs[region]['time'] = datetime.now()
        return self.addrs[region]['res']

    def get_subnets(self, region):
        if region not in self.subnets or self.get_time_diff(self.subnets[region]['time']) > self.timeout:
            self.get_vpc_conn(region)
            self.subnets[region] = {}
            self.subnets[region]['res'] = self.vpcconn.get_all_subnets()
            self.subnets[region]['time'] = datetime.now()
        return self.subnets[region]['res']

    def get_loadbalancers(self, region):
        if region not in self.loadbs or self.get_time_diff(self.loadbs[region]['time']) > self.timeout:
            self.get_elb_conn(region)
            self.loadbs[region] = {}
            self.loadbs[region]['res'] = self.elbconn.get_all_load_balancers()
            self.loadbs[region]['time'] = datetime.now()
        return self.loadbs[region]['res']

def flatten_tags(tags):
    return ', '.join("%s=%r" % (key,str(val)) for (key,val) in tags.iteritems())

creds = config.get_ec2_conf()
aws = AWSDash(creds['AWS_ACCESS_KEY_ID'], creds['AWS_SECRET_ACCESS_KEY'])

@app.route('/')
def index():
    list = []

    for region in config.region_list():
        zones = aws.get_zones(region)
        instances = aws.get_instances(region)
        ebs = aws.get_ebs(region)
        subnets = aws.get_subnets(region)

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
            'subnet_counter': len(subnets), 'ip_low_subnet': ip_low_subnet})
    return render_template('index.html', list=list)


@app.route('/ebs_volumes/<region>/')
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
    elis = aws.get_addresses(region)
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


@app.route('/instances/<region>/')
def instances(region=None):
    instances = aws.get_instances(region)
    instance_list = []
    for instance in instances:
        #start = datetime.now()
        instance_name = aws.get_instance_info(region, instance.id)
        #print (datetime.now()-start).seconds
        instance_info = {
            'instance_id': instance.id,
            'instance_state': instance.state_name,
            'instance_zone': instance.zone,
            'instance_name': instance_name[0].instances[0].tags['Name'],
            'instance_type': instance_name[0].instances[0].instance_type,
            'instance_ami': instance_name[0].instances[0].image_id,
            'instance_private_ip': instance_name[0].instances[0].private_ip_address,
            'instance_public_ip': instance_name[0].instances[0].ip_address,
            'instance_dns_name': instance_name[0].instances[0].dns_name,
            'instance_vpc': instance_name[0].instances[0].vpc_id,
            'instance_tags': flatten_tags(instance_name[0].instances[0].tags)}
        instance_list.append(instance_info)
    return render_template('instances.html', instance_list=instance_list)


@app.route('/elbimproper/<region>/')
def elbimproper(region=None):
    elbs = aws.get_loadbalancers(region)
    badelb = []
    for elb in elbs:
        elb_info = {'elb_name': elb.dns_name, 'elb_attached_instances': elb.instances,
        'elb_healthcheck': elb.health_check}
        badelb.append(elb_info)
    return render_template('elb.html', badelb=badelb)


@app.route('/vpc/subnet/<region>/')
def subnet(region=None):
    subnets = aws.get_subnets(region)
    vpc_subnets = []
    for subnet in subnets:
        subnet_info = {'subnet_id': subnet.id, 'subnet_vpc': subnet.vpc_id, 'subnet_state': subnet.state,
        'subnet_cidr': subnet.cidr_block, 'subnet_az': subnet.availability_zone,
        'subnet_avail_ip': subnet.available_ip_address_count, 'subnet_tags': flatten_tags(subnet.tags)}
        vpc_subnets.append(subnet_info)
    return render_template('subnet.html', vpc_subnets=vpc_subnets)


if __name__ == '__main__':
    app.debug = config.app_debug()
    app.run(host=config.listen_host(), port=config.listen_port())
