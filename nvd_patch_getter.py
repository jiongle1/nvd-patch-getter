'''
Further description of the code

This code only works for patches available from github, other websites are
ignored.

Takes in string of the example form, "CVE-2024-21665"
Use NVD API to go and search for available 'patch' tag
If available, default is to download locally to <curr-dir>/<cve_id>.patch
    ---- commented code is to save it to a folder named "patches" ----
Else, return False
'''

import requests
import os
import argparse

from logger_module import logger

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FOLDERNAME = "patches"


def main():
    args = parse_arguments()
    cve_id = args.cve_id
    #local_dir_check_create(FOLDERNAME)
    cve_json = nvd_cve_id_check(cve_id)
    github_bool = github_check(cve_json)
    if github_bool:
        cve_patch_link = parse_patch(cve_json)
        if cve_patch_link:
            download_cve_patch(cve_patch_link, cve_id)
        else:
            logger.info("CVE ID refers to a Github repository, but does not have patch")
            logger.info("Exiting")
            return""
    else:
        logger.info("CVE ID does not refer to a Github repository")
        logger.info("Exiting")
        return""
    

def download_cve_patch(cve_patch_link, cve_id):
    # Add a '.patch' to the end of patch URL to download it
    cve_patch_url = cve_patch_link + ".patch"
    response = requests.get(cve_patch_url)
    #filename = "./" + FOLDERNAME + '/' + cve_id + ".patch"
    filename = cve_id + ".patch"

    if response.status_code == 200:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(response.text)
        logger.info(f"Patch written to {filename}")
    else:
        logger.info(f"Patch download failed, Error: {response.status_code}")
        return""


def parse_patch(cve_json):
    # get list of references
    list_references = cve_json['vulnerabilities'][0]['cve']['references']
    for reference_dict in list_references:
        # only get patch from github source
        if reference_dict['source'] == "security-advisories@github.com":
            for tag_item in reference_dict['tags']:
                if tag_item == "Patch":
                    patch_url = reference_dict['url']
                    logger.info(f"URL to download patch is: {patch_url}")
                    return patch_url
                else:
                    pass
        else:
            pass
    logger.info(f"Patch is not found")
    return ""


def github_check(cve_json):
    # get sourceIdentifier
    # Github vulnerabilities are from github itself
    sourceIdentifier = cve_json['vulnerabilities'][0]['cve']['sourceIdentifier']
    if sourceIdentifier == "security-advisories@github.com":
        logger.info("CVE ID references to Github")
        return True
    else:
        logger.info("CVE ID does not reference to Github, try another ID")
        return False


def nvd_cve_id_check(cve_id):
    # Check if api can return cve_id
    # e.g https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
    cve_url = NVD_API_URL + "?cveId=" + cve_id
    response = requests.get(cve_url)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        logger.info(f"CVE ID does not exist on NVD, Error: {response.status_code}")
        return""
    

def local_dir_check_create(FOLDERNAME):
    # Check if current directory has folder named "patches"
    # Create if it does not exist
    curr_dir = os.getcwd()
    target_dir = os.path.join(curr_dir, FOLDERNAME)

    if not os.path.exists(target_dir):
        logger.info("Folder named patches does not exist! Creating...")
        os.makedirs(target_dir)
        logger.info("Folder patches created")
    else:
        logger.info("Folder patches exists")


def parse_arguments():
    parser = argparse.ArgumentParser(description='Takes in cve-id and downloads patch file from NVD website')
    parser.add_argument('-id', '--cve_id', help='CVE ID input')
    return parser.parse_args()


if __name__ == "__main__":
    main()