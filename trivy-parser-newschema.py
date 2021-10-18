#!/usr/bin/python3
#Coded By Ashkan Rafiee


import json


# Load json locally
def load_json(json_filename):
    # Opening JSON file
    with open(json_filename) as f:
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
    for package in package_list["Results"]:
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
            if vulnerability["Severity"] == "INFO" or vulnerability["Severity"] == "LOW" or vulnerability["Severity"] == "MEDIUM" or vulnerability["Severity"] == "HIGH" or vulnerability["Severity"] == "CRITICAL":
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
    avail_for_remedy = []
    not_available = []
    pklist = []
    for package in finalized_packages.values():
        for vulnerability in package["Vulnerabilities"]: 
            PkgName = package["Vulnerabilities"][vulnerability]["PkgName"]
            # title = package["Vulnerabilities"][vulnerability]["Title"]
            cve = package["Vulnerabilities"][vulnerability]["VulnerabilityID"]
            severity = package["Vulnerabilities"][vulnerability]["Severity"]
            cvss = package["Vulnerabilities"][vulnerability]["CVSS"]
            reference = package["Vulnerabilities"][vulnerability]["References"]
            if "FixedVersion" in package["Vulnerabilities"][vulnerability]:
                InstalledVersion = package["Vulnerabilities"][vulnerability]["InstalledVersion"]
                FixedVersion = package["Vulnerabilities"][vulnerability]["FixedVersion"]
                PackageVulns = {cve:{'Fixed Version':FixedVersion,'Severity':severity, 'CVSS':cvss, 'Reference':reference}}
                availabe_list.append({'Package Name':PkgName,'Installed Version': InstalledVersion,'Vulnerabilities':PackageVulns})
                pklist.append(PkgName)
                avail_for_remedy.append(f'Update {PkgName} From {InstalledVersion} ----> {FixedVersion}')
            else:
                not_available.append(f'{PkgName} ----> {cve}')
                pklist.append(PkgName)  

    not_available = set(not_available)
    not_available = list(not_available)

    avail_for_remedy = set(avail_for_remedy)
    avail_for_remedy = list(avail_for_remedy)

    pklist = set(pklist)
    pklist = list(pklist)

    remediation_dict = {"Update Needed":avail_for_remedy,"No Remediation":not_available,"Vulnearble Packages":pklist}

    return (availabe_list, remediation_dict)

# Merge Same Name Packages
def deepmerger(availabe_list):
    update_dict = {}

    for item in availabe_list:
        update_dict.update({item["Package Name"]:{'Installed Version': item["Installed Version"],'Vulnerabilities':item["Vulnerabilities"]}})
        
    for item in availabe_list:
        for pkg,values in update_dict.items():
            if item["Package Name"] == pkg:
                values["Vulnerabilities"].update(item["Vulnerabilities"])
    for pkg,values in update_dict.items():
        version_list = []
        for itm,vuln in values["Vulnerabilities"].items():
            version_list.append(vuln["Fixed Version"])
        version_list = set(version_list)
        version_list = list(version_list)
        update_dict[pkg]["Update to latest listed here"] = version_list

    return update_dict


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
    availabe_list, remediation_dict = remediation(finalized_packages)
    # Save Remediations
    save_json(remediation_dict,'remediations.json')
    # Merge Same Name Packages
    update_dict = deepmerger(availabe_list)
    # Save Update List
    save_json(update_dict,"update_list.json")




if __name__ == '__main__':
    main()
