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


# def get_total_rules():
#     return 250

# def get_total_compliance_framework():
#     return 9