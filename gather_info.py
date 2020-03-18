import logging


def get_org_name():
    return "Company Inc."

def get_account_info():
    account_info = {
        "accounts": 470,
        "rules": 250,
        "compliance_frameworks": 9,
        "total_violations": 810
    }
    return account_info

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
    provider = []
    aws_violations =  456
    azure_violations = 4360
    provider.append(aws_violations)
    provider.append(azure_violations)
    result = []
    result.append(provider)
    return result

def get_open_resolved_findings():
    info = {
        "open": 98561,
        "resolved": 8000
    }
    return info

def get_top_10_accounts_by_findings():
    #result = [[100,50], [1000, 250], [1000, 250], [1000, 250], [1000, 150], [1000, 250], [10, 250], [1000, 45], [1000, 36], [100, 250]]
    result = [
        [100,1000,250, 150, 250, 45, 250, 800, 500, 325],
        [35,42,89, 120, 123, 457, 125, 369, 850, 100]
    ]
    
    accounts = ["Acc1", "Acc2", "Acc3", "Acc4", "Acc5", "Acc6", "Acc7", "Acc8", "Acc9", "Acc10"]
    return result, accounts


# def get_total_rules():
#     return 250

# def get_total_compliance_framework():
#     return 9