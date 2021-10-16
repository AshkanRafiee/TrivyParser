#!/usr/bin/python3
#Coded By Ashkan Rafiee


import json


# Load json locally
def load_json(json_filename):
    # Opening JSON file
    with open(json_filename, encoding='utf-8') as f:
        # returns JSON object as a dictionary
        data = json.load(f)
    return data


# Save json locally
def save_json(list_of_dicts,save_name):
    with open(save_name, 'w') as fout:
        json.dump(list_of_dicts, fout)


# Remove dicts without vulnerability
def vulnerable_finder(package_list):
    vulnerable_packages = []
    for package in package_list:
        if "Vulnerabilities" in package:
            vulnerable_packages.append(package)
    return vulnerable_packages


# Index desired positions
def indexer(package_list):
    index_list = []
    p = 0
    for package in package_list:
        v = 0
        for vulnerability in package["Vulnerabilities"]:
            if vulnerability["Severity"] == "HIGH" or vulnerability["Severity"] == "CRITICAL":
                index_list.append((p,v))
            v += 1
        p += 1
    return index_list


# Add qualified packages
def package_adder(package_list,index_list):
    qualified_packages = []
    for index in index_list:
        p,v = index
        temp_dict = {}
        temp_dict["Target"] = package_list[p]["Target"]
        temp_dict["Type"] = package_list[p]["Type"]
        temp_dict["Vulnerabilities"] = package_list[p]["Vulnerabilities"][v]
        qualified_packages.append(temp_dict)
    return qualified_packages


# Merge same name packages
def merger(qualified_packages):
    finalized_packages = {}
    for package in qualified_packages:
        if package["Target"] in finalized_packages:
            finalized_packages[package["Target"]]["Vulnerabilities"][package["Vulnerabilities"]["VulnerabilityID"]] = package["Vulnerabilities"]
        else:
            finalized_packages[package["Target"]] = {"Type":package["Type"], "Vulnerabilities":{package["Vulnerabilities"]["VulnerabilityID"]:package["Vulnerabilities"]}}
    return finalized_packages


# Export remediation from available packages
def remediation(finalized_packages):
    availabe_list = []
    not_available = []
    pklist = []
    for package in finalized_packages.values():
        for vulnerability in package["Vulnerabilities"]: 
            PkgName = package["Vulnerabilities"][vulnerability]["PkgName"]
            cve = package["Vulnerabilities"][vulnerability]["VulnerabilityID"]
            if "FixedVersion" in package["Vulnerabilities"][vulnerability]:
                InstalledVersion = package["Vulnerabilities"][vulnerability]["InstalledVersion"]
                FixedVersion = package["Vulnerabilities"][vulnerability]["FixedVersion"]

                availabe_list.append(f'Update {PkgName} From {InstalledVersion} ----> {FixedVersion}')
                pklist.append(PkgName)
            else:
                not_available.append(f'{PkgName} ----> {cve}')
                pklist.append(PkgName)

    availabe_list = set(availabe_list)
    availabe_list = list(availabe_list)

    # Save Update List
    save_json(availabe_list,"update_list.json")

    not_available = set(not_available)
    not_available = list(not_available)

    pklist = set(pklist)
    pklist = list(pklist)


    remediation_dict = {"Update Needed":availabe_list,"No Remediation":not_available,"Vulnearble Packages":pklist}
    return remediation_dict


# Main script
def main():
    # Load trivy json file
    package_list = load_json("gl-container-scanning-report.json")
    # Remove not vulnerable packages
    vulnerable_packages = vulnerable_finder(package_list)
    # Find index of desired severities
    desired_indexes = indexer(vulnerable_packages)
    # Select qualified packages
    qualified_packages = package_adder(vulnerable_packages,desired_indexes)
    # Merge duplicate items
    finalized_packages = merger(qualified_packages)
    # Save vulnerable packages
    save_json(finalized_packages,'vulnerable_packages.json')
    # Find available remediations
    remediation_dict = remediation(finalized_packages)
    # Save Remediations
    save_json(remediation_dict,'remediations.json')



if __name__ == '__main__':
    main()
