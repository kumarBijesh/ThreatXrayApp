import requests
import time

API_KEY = "4cd6af0e44088f1a5c05c4f244e4c7d3dd9b8f4eaf920114e1f23301c5b0a3a5"  
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

def submit_url(url):
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = f"url={url}"

    response = requests.post(VT_URL_SCAN, headers=headers, data=data)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        return analysis_id
    return None

def check_url_analysis(analysis_id):
    headers = {
        "x-apikey": API_KEY
    }

    while True:
        response = requests.get(VT_ANALYSIS_URL.format(analysis_id), headers=headers)
        result = response.json()
        status = result["data"]["attributes"]["status"]

        if status == "completed":
            stats = result["data"]["attributes"]["stats"]
            return stats  # Return the stats dictionary
        time.sleep(5)