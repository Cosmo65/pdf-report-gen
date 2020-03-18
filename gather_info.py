import logging
import requests
import os
import json
import sys


access_token = ''

refresh_token = os.environ['REFRESH_TOKEN']

class ErrorStatusCode(Exception):
    pass

## Get Access Token from CSP
def auth():

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize'
    payload = {"refresh_token": refresh_token }

    response = requests.post(url, data=payload , headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()

    data = json.loads(response.content)

    global access_token
    access_token = data["access_token"]

def all_findings():

    global access_token

    headers = {
        'Content-Type' : 'application/json', 
        'Authorization': 'Bearer {}'.format(access_token)
    }
    payload = "{\n}"
    url = 'https://api.securestate.vmware.com/v2/findings/query'
    response = requests.post(url , data=payload, headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()

    # Fetch the continuation Token
    data = json.loads(response.content)
    continuationToken = data["continuationToken"]

    # Get the entire payload for 1000 objects
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }

    # replace cloud provider key with "AWS" for Amazon web services related violations
    payload = {
                "filters": {
                    "cloudProvider": "AWS"
                    },
                "paginationInfo":{
                    "continuationToken": continuationToken,
                    "pageSize":1000
                    }
            }

    url = 'https://api.securestate.vmware.com/v2/findings/query'
    response = requests.post(url , data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit() 

    return response

def vss_account_info():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
                "aggregations": {
                            "find": {
                                "fieldName":
                                "CloudProvider",
                                "aggregationType": "Terms"
                                },
                            "accounts": {
                                "fieldName":"CloudAccountId",
                                "aggregationType":"Terms",
                                "termsCount":10
                                }
                            }
               }    
        
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()   
    
    with open("data/account_info.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()
    
def vss_rules():
    url = "https://api.securestate.vmware.com/v1/rules/query"
    payload = "{\n}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=payload, headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
            
    with open("data/rules_info.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()

def vss_open_resolved_findings():
   
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
                "aggregations": {
                        "accounts":{
                                "fieldName": "CloudAccountId",
                                "aggregationType":"Terms"
                                }
                        },
                "filters":{
                    "status":"Resolved"
                    }
            }
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/resolved_findings.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()
    
def vss_frameworks():
    url = "https://api.securestate.vmware.com/v1/compliance-frameworks"
    payload = {}    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.get(url, headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/frameworks.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()


def vss_top_10_high_violating_accounts():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    
    top_10_account = []
    
    for account in open_accounts:
        top_10_account.append(account)   
    
    url = "https://api.securestate.vmware.com/v2/findings/query"

    payload = {
                "aggregations":{
                            "agg":{
                                "fieldName":"CloudAccountId",
                                "aggregationType":"Terms"
                                }
                    },
                "filters":{
                        "cloudAccountIds": top_10_account,
                        "levels":["High"],
                        "status":"Open"
                        }
            }
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/high_severity.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()


def get_org_name():
    return "Company Inc."

def get_account_info():

    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    with open("data/rules_info.json", "r") as rules_info:
        rules = json.load(rules_info)
    rules_info.close()
    
    with open("data/frameworks.json", "r") as frameworks_info:
        frameworks = json.load(frameworks_info)
    frameworks_info.close()
    

    dict_accounts = accounts["aggregations"]["accounts"]["buckets"]
    total_accounts = len(dict_accounts.keys())
    
    account_info = {
        "accounts": total_accounts,
        "rules": rules["totalCount"],
        "compliance_frameworks": frameworks["totalCount"],
        "total_violations": accounts["totalCount"]
    }
    
    return account_info


def get_open_resolved_findings():
    
    with open("data/account_info.json", "r") as findings:
        open_findings = json.load(findings)
    findings.close()
    
    with open("data/resolved_findings.json", "r") as findings:
        resolved_findings = json.load(findings)
    findings.close()
    
    data = {
        "open": open_findings["totalCount"],
        "resolved": resolved_findings["totalCount"]
    }
    return data
    

def get_config():
    config = {
        "provider": ["AWS", "Azure"],
        "cloud_accounts": 470,
        "compliance_frameworks": 9,
        "severity": ["High", "Medium"],
        "cloud_tag": "All",
        "environment": "All"
    }

    return config

def get_findings_by_provider():
    
    with open("data/account_info.json", "r") as account_info:
        accounts = json.load(account_info)
    account_info.close()
    
    provider = []
    provider.append(accounts["aggregations"]["find"]["buckets"]["aws"]["count"])
    provider.append(accounts["aggregations"]["find"]["buckets"]["azure"]["count"])
    result = []
    result.append(provider)
    return result


def get_top_10_accounts_by_findings():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    with open("data/resolved_findings.json", "r") as output_file:
        findings = json.load(output_file)
    output_file.close()

    account_ids = []
    
    open_findings = []
    resolved_findings = []
    resolved_accounts = findings["aggregations"]["accounts"]["buckets"]
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    sorted_open_accounts = dict(sorted(open_accounts.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    
    logging.info(sorted_open_accounts)
    total_accounts = max(len(resolved_accounts.keys()), len(open_accounts))
    for open_account in sorted_open_accounts:
        logging.info(sorted_open_accounts[open_account]["count"])
        if(open_account in resolved_accounts):
            resolved_findings.append(resolved_accounts[open_account]["count"])
            open_findings.append(sorted_open_accounts[open_account]["count"])
        else:
            resolved_findings.append(0)
            open_findings.append(sorted_open_accounts[open_account]["count"])
        ## @TODO - Change account ID logic with inventory service API    
        account_ids.append(open_account)

    result = [
        open_findings,
        resolved_findings
    ]
    
    return result, account_ids

def gather_data():
    logging.info("Gathering Account Info\n")
    vss_account_info()
    logging.info("Gathering Rules Info\n")
    vss_rules()
    logging.info("Gathering Frameworks Info\n")
    vss_frameworks()
    logging.info("Gathering Open and Resolved Findings\n")
    vss_open_resolved_findings()
    logging.info("Gathering High Violations")
    vss_top_10_high_violating_accounts()
    
    
# def get_total_rules():
#     return 250

# def get_total_compliance_framework():
#     return 9