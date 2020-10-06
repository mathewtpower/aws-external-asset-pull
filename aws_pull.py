#!/usr/bin/env python3
import boto3
import config
from datetime import datetime
import requests
import json
import logger
from tenable.io import TenableIO

regions = ["us-east-1","us-east-2","us-west-1","us-west-2","ap-south-1","ap-northeast-2","ap-southeast-1","ap-southeast-2","ap-northeast-1","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","eu-north-1","sa-east-1"]
logger = logger.get_logger(__name__, config.logging['log_file'], config.logging['log_level'])

def pushToSplunk(assets):
    for account in config.splunk:
        logger.info("Preparing to push asset details to Splunk")
        rest_api_url=config.splunk[account]['rest_api_url']
        logger.debug("Rest API URL set to: " + rest_api_url)
        r = requests.post(rest_api_url, auth=(config.splunk[account]['username'], config.splunk[account]['password']), verify=False, json=assets)
        logger.info("Response for HTTP request for " + account + " search head: " + str(r))
        logger.debug("Full response text for HTTP request for " + account + " search head: " + str(r.text))

def pushToTenable(externalIPs):
    logger.info("Preparing to push external IP addresses to Tenable.io target group")
    tio = TenableIO(config.tenable['access_key'], config.tenable['secret_key'])
    tio.target_groups.edit(config.tenable['target_group_id'], name=config.tenable['target_group_name'],members=externalIPs)

def awsAssetPull():
    awsAssets = []
    awsExternalIPs = []
    for account in config.aws:
        logger.info("Iterating through AWS accounts. Currently on: " + account)
        aws_access_key_id=config.aws[account]['access_key']
        aws_secret_access_key=config.aws[account]['secret_key']
        session = boto3.Session(
            aws_access_key_id,
            aws_secret_access_key
        )
        for region in regions:
            logger.debug("Iterating through regions, currently on region " + region + "for account " + account)
            client=session.client('ec2', region_name=region)
            try:
                results = client.describe_instances()
            except:
                logger.warn("Error for account: " + account + " in region: " + region)
                pass

            reservations = results['Reservations']
            
            for reservation in reservations:
                instances = reservation['Instances']
                for instance in instances:
                    if 'PublicIpAddress' in instance:
                        if instance['State'] != 'stopped':
                            instanceName = next(tag for tag in instance['Tags'] if tag['Key'] == 'Name')['Value']
                            instanceName = instanceName.replace('(', '').replace(')', '')
                            date=datetime.now().strftime('%d-%b-%Y')
                            awsAssets.append({"_key":instance['InstanceId'],"last_detected":date,"instance_id":instance['InstanceId'],"instance_name":instanceName,"public_dns":instance['PublicDnsName'],"public_ip":instance['PublicIpAddress'],"private_ip":instance['PrivateIpAddress']})
                            awsExternalIPs.append(instance['PublicIpAddress'])
    pushToSplunk(awsAssets)
    pushToTenable(awsExternalIPs)

if __name__ == '__main__':
    logger.info('Pulling AWS asset information')
    awsAssetPull()