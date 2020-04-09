# PDF Report Gen for VMware Secure State

### This repo includes a python script that can be used to generate compliance report in PDF format for VMware Secure State

#### The repo uses publicly available APIs for Secure State - api.securestate.vmware.com

#### Requirements

* Works on both Linux and Windows

1. virtualenv (Optional but recommended) 
2. Python3.7 or higher
3. pip3
4. pip3 install -r requirements.txt

#### Generating Report

1. Modify the configuration file based on your requirements. The file should be `.json` format. 

Here are some sample config files.

* Sample 1

```json{
    "org_name":"Test Inc",
    "config":{
        "providers": ["AWS", "Azure"],
        "severity": ["High", "Medium", "low"],
        "cloudTags":{},
        "cloudAccountIds":["All"]
    }
}
```

* Sample 2

```json{
    "org_name":"Demo Inc",
    "config":{
        "providers": ["AWS"],
        "severity": ["High"],
        "cloudTags":{"alpha.eksctl.io/cluster-name": ["acme-rds"], "owner":["developer"]},
        "cloudAccountIds":["12345679012", "22325145250"]
    }
}
```

2. Obtain the `Refresh Token` from CSP portal and set the environment variable

```export REFRESH_TOKEN=<your_token_here>```

3. Run the command from cli. Configuration file name and output file name are required arguments.

```python3 generate.py --config config.json --output-file vss_report```

4. Run `python3 generate.py -h` to get help and description

#### Refer to the License file for more details

MIT License

Copyright (c) 2020 Shrivatsa Upadhye

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.