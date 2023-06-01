import json 
import os
import re
import sys
import re 
import urllib.request 
 
 #pull the name of the extension using the google chrome extension store with a given id. local methods are hit or miss compared to this
def get_name_from_id(extension_id):
    url = f"https://chrome.google.com/webstore/detail/Text/{extension_id}?hl=en" 
    with urllib.request.urlopen(url, timeout=5) as response:
        html = response.read().decode("utf-8") 
        match = re.search(r"<h1 class=\"e-f-w\">(.+?)</h1>", html) 
        if match: 
            extension_name = match.group(1) 
            return extension_name
        else: 
            extension_name = "temporary_connection_error_FIX"
            print("Extension name not found.") 


# check if the current dictionary contains the key 
def search_json(json_dict, key_name): 
    key_value = json_dict.get(key_name) 
    if key_value is not None: 
        return key_value 

    # key not found in current dictionary, search in nested dictionaries 
    for value in json_dict.values(): 
        if isinstance(value, dict):  # value is a dictionary, search for the key in it 
            key_value = search_json(value, key_name) 
        if key_value is not None: 
            return key_value 

    return "N/A"

def compare_extension_permissions(permissions_list):
    linked_dict = {}
    permission_link_dict = json.load(open(os.path.relpath("db/permissions.json")))
    for permission in permissions_list:
        search_result = search_json(permission_link_dict,permission)
        if search_result != "N/A":
            linked_dict[permission] = search_json(permission_link_dict,permission)
            linked_dict[permission]["name"] = permission
        elif (re.compile("https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)") is not None): #domain pattern
            linked_dict[permission] = {
        "name": permission,
        "description": "Matches any URL that uses the https: scheme.",
        "warning": "Read and change all your data on the websites you visit that uses the scheme  "+ permission +"",
        "risk": "high"}
        else: sys.exit("permission not found") #this code exits the program, consider replacing it with "soft error" 

    return linked_dict
