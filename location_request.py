import urllib.request
import json

ENDPOINT = 'http://api.ipstack.com/'
KEY = 'access_key=17623fd5de0423248fa1560eec479bd9'    

def parse_IP(address):
    field = address
    output = 'json'
    request = ENDPOINT + field + "?" + KEY
    response = urllib.request.urlopen(request).read()
    response = response.decode("utf-8")
    output = json.loads(response)
    s = json.dumps(output, indent=4, sort_keys=True)
    return json.loads(s)

def get_cityAddr_tup(obj):
    return (obj["region_code"], obj["city"])

def get_country_tup(obj):
    return (obj["country_code"], obj["country_name"])

def get_coor_tup(obj):
    return (obj["latitude"], obj["longitude"])

def get_time_tup(obj):
    zone = obj["time_zone"]
    return (zone["id"], zone["current_time"], zone["code"])