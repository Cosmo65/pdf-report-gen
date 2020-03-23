import logging
import requests
import os
import json
import sys
from operator import itemgetter

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
    
def vss_all_rules():
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
            
    with open("data/all_rules_info.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()

def vss_top_10_rules():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    
    payload = {
	    "aggregations":{
		    "rules":{
			    "fieldName":"RuleId",
			    "aggregationType": "Terms",
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
    
    with open("data/rules_info_top_10.json", "w") as output_file:
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

def vss_high_med_low_top_10_findings():
    
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
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    "subAggregations": {
                        "high":{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                        }
                    }
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
    
    with open("data/high_severity_top_10.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()

    #Medium Severity
    
    url = "https://api.securestate.vmware.com/v2/findings/query"

    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    "subAggregations": {
                        "medium":{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                        }
                    }
                }
            },
            "filters":{
                "cloudAccountIds": top_10_account,
                "levels":["Medium"],
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
    
    with open("data/medium_severity_top_10.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()


    url = "https://api.securestate.vmware.com/v2/findings/query"

    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    "subAggregations": {
                        "low":{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                        }
                    }
                }
            },
            "filters":{
                "cloudAccountIds": top_10_account,
                "levels":["Low"],
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
    
    with open("data/low_severity_top_10.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()

def vss_suppressed_findings():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",

                    "subAggregations": {
                        "suppressed":{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                            
                        }
                    }
                }
            },
            "filters":{
                "isSuppressed": True
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
    
    with open("data/suppressed_findings.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()

def vss_all_violations_by_severity():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
            },
            "filters":{
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
    
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
                },
            "filters":{
                "levels":["Medium"],
                "status":"Open"
                }
        }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/medium_severity.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()
    
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
                },
            "filters":{
                "levels":["Low"],
                "status":"Open"
                }
            }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/low_severity.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()


def vss_top_10_objects_by_risk():
    url = "https://api.securestate.vmware.com/v2/findings/query"
    
    payload = {
                "aggregations":{
                    "provider":{
                        "fieldName":"CloudProvider",
                        "aggregationType":"Terms",
                        "subAggregations":{
                                "findingsCount":{
                                    "fieldName":"ObjectXid",
                                        "aggregationType":"Terms",
                                        "termsCount":10,
                                            "subAggregations":{

                                            "AccountId":{
                                            "fieldName":"CloudAccountId",
                                                "aggregationType":"Terms",
                                            "subAggregations":{
                                                "riskSummary":{
                                                    "fieldName":"RiskScore",
                                                    "aggregationType":"Terms",
                                                        "subAggregations":{
                                                            "resourceName":{
                                                                "fieldName":"ObjectId",
                                                                "aggregationType":"Terms"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                },
                "filters":{
                    "status":"Open",
                    "descending":True
                    
                }
            }
    
    headers = {
        'Content-Type':'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    with open("data/objects_risk_top_10.json", "w") as output_file:
        json.dump(response.json(), output_file, indent=4)
    output_file.close()
    

def get_org_name():
    return "Company Inc."

def get_account_info():

    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    with open("data/all_rules_info.json", "r") as rules_info:
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
    
    total_accounts = max(len(resolved_accounts.keys()), len(open_accounts))
    for open_account in sorted_open_accounts:
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


def get_high_med_low_top_10_violations():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()

    with open("data/high_severity_top_10.json", "r") as severity_info:
        high_sev = json.load(severity_info)
    severity_info.close()
    
    with open("data/medium_severity_top_10.json", "r") as severity_info:
        medium_sev = json.load(severity_info)
    severity_info.close()
    
    with open("data/low_severity_top_10.json", "r") as severity_info:
        low_sev = json.load(severity_info)
    severity_info.close()
    
    aws_suppressed_findings = {}
    azure_suppressed_findings = {}
    aws_accounts_high_sev = {}
    azure_accounts_high_sev = {}
    aws_accounts_med_sev = {}
    azure_accounts_med_sev = {}
    aws_accounts_low_sev = {}
    azure_accounts_low_sev = {}
    
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    sorted_open_accounts = dict(sorted(open_accounts.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    if("aws" in high_sev["aggregations"]["cloud"]["buckets"]):
        aws_accounts_high_sev = high_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["high"]["buckets"]
    if("azure" in high_sev["aggregations"]["cloud"]["buckets"]):
        azure_accounts_high_sev = high_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["high"]["buckets"]
        
    if("aws" in medium_sev["aggregations"]["cloud"]["buckets"]):
        aws_accounts_med_sev = medium_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["medium"]["buckets"]
    if("azure" in medium_sev["aggregations"]["cloud"]["buckets"]):
        azure_accounts_med_sev = medium_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["medium"]["buckets"]
    
    if("aws" in low_sev["aggregations"]["cloud"]["buckets"]):
        aws_accounts_low_sev = low_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["low"]["buckets"]
    if("azure" in low_sev["aggregations"]["cloud"]["buckets"]):
        azure_accounts_low_sev = low_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["low"]["buckets"]
    
    
    with open("data/suppressed_findings.json", "r") as suppressed_info:
        suppressed_findings = json.load(suppressed_info)
    suppressed_info.close()
    
    if("aws" in suppressed_findings["aggregations"]["cloud"]["buckets"]):
        aws_suppressed_findings = suppressed_findings["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["suppressed"]["buckets"]
    if("azure" in suppressed_findings["aggregations"]["cloud"]["buckets"]):
        azure_suppressed_findings = suppressed_findings["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["suppressed"]["buckets"]
       

    final_result = []
    
    for account in sorted_open_accounts:
        high = 0
        medium = 0
        low = 0
        suppressed = 0
            
        if (account in aws_accounts_high_sev):
            high = aws_accounts_high_sev[account]["count"]
            provider = "AWS"
        elif(account in aws_accounts_high_sev):
            high = azure_accounts_high_sev[account]["count"]
            provider = "Azure"
        if (account in aws_accounts_med_sev):
            med = aws_accounts_med_sev[account]["count"]
            provider = "AWS"
        elif(account in azure_accounts_med_sev):
            med = azure_accounts_med_sev[account]["count"]
            provider = "Azure"
        if (account in aws_accounts_low_sev):           
            low = aws_accounts_low_sev[account]["count"]         
            provider = "AWS"
        elif(account in azure_accounts_low_sev):
            low = azure_accounts_low_sev[account]["count"]
            provider = "Azure"
        if (account in aws_suppressed_findings):
            suppressed = aws_suppressed_findings[account]["count"]
            provider = "AWS"
        elif(account in azure_suppressed_findings):
            suppressed = azure_suppressed_findings[account]["count"]
            provider = "Azure"
            
        data = []
        data.append(provider)
        data.append(account)
        data.append(high)
        data.append(med)
        data.append(low)
        data.append(suppressed)
        final_result.append(data)

    return final_result
    
def get_all_violations_by_severity():
    
    with open("data/high_severity.json", "r") as output_file:
        high = json.load(output_file)
    output_file.close()
    
    with open("data/medium_severity.json", "r") as output_file:
        medium = json.load(output_file)
    output_file.close()
    
    with open("data/low_severity.json", "r") as output_file:
        low = json.load(output_file)
    output_file.close()
    
    aws_high = 0 
    azure_high = 0
    aws_med = 0 
    azure_med = 0    
    aws_low = 0 
    azure_low = 0 
    
    
    if("aws" in high["aggregations"]["cloud"]["buckets"]):
        aws_high = high["aggregations"]["cloud"]["buckets"]["aws"]["count"]
    if("azure" in high["aggregations"]["cloud"]["buckets"]):
        azure_high = high["aggregations"]["cloud"]["buckets"]["azure"]["count"]
    
    if("aws" in medium["aggregations"]["cloud"]["buckets"]):
        aws_med = medium["aggregations"]["cloud"]["buckets"]["aws"]["count"]
    if("azure" in medium["aggregations"]["cloud"]["buckets"]):
        azure_med = medium["aggregations"]["cloud"]["buckets"]["azure"]["count"]
        
    if("aws" in low["aggregations"]["cloud"]["buckets"]):
        aws_low = low["aggregations"]["cloud"]["buckets"]["aws"]["count"]
    if("azure" in low["aggregations"]["cloud"]["buckets"]):
        azure_low = low["aggregations"]["cloud"]["buckets"]["azure"]["count"]
    
    aws = [aws_high, aws_med, aws_low]
    azure = [azure_high, azure_med, azure_low]
    
    return aws, azure
 
def get_top_10_rules():
    
    with open("data/all_rules_info.json", "r") as output_file:
        all_rules = json.load(output_file)
    output_file.close()
    
    with open("data/rules_info_top_10.json", "r") as output_file:
        rules = json.load(output_file)
    output_file.close()
    
    result = []
    top_10_rules = rules["aggregations"]["rules"]["buckets"]
    sorted_top_10_rules = dict(sorted(top_10_rules.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    for rule in sorted_top_10_rules:
        for item in all_rules["results"]:
            data = []
            if(item["id"]==rule):
                name = item["name"]
                provider = item["provider"]
                object_type = item["service"]
                severity = item["level"]
                count = top_10_rules[rule]["count"]
                data.append(name)
                data.append(provider)
                data.append(object_type)
                data.append(severity)
                data.append(count)
                result.append(data)

    return result
                            
def get_top_10_objects_by_risk():
    with open("data/objects_risk_top_10.json", "r") as object_risks_info:
        objects_top_10 = json.load(object_risks_info)
    object_risks_info.close()
    
    aws_object_ids = objects_top_10["aggregations"]["provider"]["buckets"]["aws"]["subAggregations"]["findingsCount"]["buckets"]
    azure_object_ids = objects_top_10["aggregations"]["provider"]["buckets"]["azure"]["subAggregations"]["findingsCount"]["buckets"]

    result = []
    for obj in aws_object_ids:
        data = []
        provider = "AWS"
        objectId = obj
        finding_data = aws_object_ids[obj]["subAggregations"]["AccountId"]["buckets"]
        account_id = list(finding_data)[0]
        count = finding_data[account_id]["count"]
        riskSummary = finding_data[account_id]["subAggregations"]["riskSummary"]["buckets"]
        score = 0
        for risk in list(riskSummary):
            score += int(risk) * riskSummary[risk]["count"]
            object_name = list(riskSummary[risk]["subAggregations"]["resourceName"]["buckets"].keys())[0]
        
        data.append(score)
        data.append(count)
        data.append(object_name)
        data.append(objectId)
        data.append(provider)
        data.append(account_id)
        result.append(data)
            
    for obj in azure_object_ids:
        data = []
        provider = "Azure"
        objectId = obj
        finding_data = azure_object_ids[obj]["subAggregations"]["AccountId"]["buckets"]
        account_id = list(finding_data)[0]
        count = finding_data[account_id]["count"]
        riskSummary = finding_data[account_id]["subAggregations"]["riskSummary"]["buckets"]
        score = 0
        for risk in list(riskSummary):
            score += int(risk) * riskSummary[risk]["count"]
            object_name = list(riskSummary[risk]["subAggregations"]["resourceName"]["buckets"].keys())[0]
        
        data.append(score)
        data.append(count)
        data.append(object_name)
        data.append(objectId)
        data.append(provider)
        data.append(account_id)
        result.append(data)
        
    result = sorted(result, key=itemgetter(0,1), reverse=True)
    result = result[0:9]
    return result
      
    

def gather_data():
    logging.info("Gathering Account Info\n")
    vss_account_info()
    logging.info("Gathering All Rules Info\n")
    vss_all_rules()
    logging.info("Gathering Frameworks Info\n")
    vss_frameworks()
    logging.info("Gathering Open and Resolved Findings\n")
    vss_open_resolved_findings()
    logging.info("Gathering Findings by severity\n")
    vss_high_med_low_top_10_findings()
    logging.info("Gathering Suppressed Findings\n")
    vss_suppressed_findings()
    logging.info("Gathering Findings by severity\n")
    vss_all_violations_by_severity()
    logging.info("Gathering Top 10 Rules\n")
    vss_top_10_rules()
    logging.info("Gathering Top 10 Objects by Risk\n")
    vss_top_10_objects_by_risk()
    

    
# def get_total_rules():
#     return 250

# def get_total_compliance_framework():
#     return 9