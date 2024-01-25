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
import json
import re
from ftplib import FTP
from urllib.parse import urlparse


from settings import logger
import settings


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FOLDERNAME = "patches"


class Nvd_Patch_Getter:

    def __init__(self, args):
        config = settings.get_config()
        self.apiKey = config['apiKey']
        logger.info("Initializing...")
        self.args = args
        self.is_in_nvd = True
        self.patch_text = ""
        self.is_cve_public_bool = True


    def run(self):
        cve_id = self.args.cve_id
        self.local_dir_check_create(FOLDERNAME)
        cve_json = self.nvd_cve_id_check(cve_id)
        if not cve_json:
            logger.warning(f"CVE ID {cve_id} does not exist on NVD or is not publicly available")
            return""
        cve_patch_link_list = self.parse_patch(cve_json)
        if cve_patch_link_list:
            self.patch_text = self.download_cve_patch(cve_patch_link_list, cve_id)
        else:
            logger.info(f"CVE ID: {cve_id} does not have patch")
            logger.info("Exiting")


    def download_cve_patch(self, cve_patch_link_list, cve_id):
        '''
        Returns empty string

        Args:
            cve_patch_link_list (list): list of patch links
            cve_id (string): Current working cve id
        Returns:
            string: ""
        '''
        # include headers for NVD API key

        for index, cve_patch_url in enumerate(cve_patch_link_list):
            try:
                response = requests.get(cve_patch_url)

                if response.status_code == 200:
                    filename = "./" + FOLDERNAME + '/' + cve_id + '_' + str(index) + ".patch"
                    with open(filename, 'w') as file:
                        file.write(response.text)
                    logger.info(f"Patch written to {filename}")
                else:
                    logger.warning(f"Patch not found. Status code: {response.status_code}")
            except:
                logger.warning(f"Patch not found. URL: {cve_patch_url}")
        return ""
    

    def parse_patch(self, cve_json):
        """returns a list of patch urls

        Args:
            cve_json (_type_): _description_

        Returns:
            a list of patch urls or an empty list
            _type_: _description_
        """
        # get list of references
        list_references = cve_json['vulnerabilities'][0]['cve']['references']
        patch_urls = []
        for reference_dict in list_references:
            # go through every URL and search for commit word in link
            any_url = reference_dict['url']
            commit_url = self.is_url_contain_commit(any_url)
            openssl_url = self.is_url_contain_openssl(any_url)
            if commit_url:
                # commit urls can come from github, savannah, openssl
                downloadable_patch_url = self.conver_commit_patch(commit_url)
                patch_urls.append(downloadable_patch_url)
            elif openssl_url:
                downloadable_patch_url = self.conver_openssl_patch(openssl_url)
                patch_urls.append(downloadable_patch_url)
            else:
                pass
        return patch_urls


    def conver_openssl_patch(self, openssl_url):
        openssl_url = re.sub('secadv_', 'secadv/', openssl_url)
        return openssl_url


    def conver_commit_patch(self, commit_url):
        # if github url, add .patch to end url
        if 'github.com' in commit_url:
            patch_url = commit_url + '.patch'
            return patch_url
        # if starts with git. , highly likely swapping the word commit with
        # patch will work
        elif 'git.' in commit_url:
            #convert ascii back to character, if any
            commit_url = re.sub(r'%3B', ';', commit_url)
            patch_url = re.sub('commit', 'patch', commit_url)
            return patch_url


    def is_url_contain_commit(self, any_url):
        if 'commit' in any_url:
            return any_url
        return ""


    def is_url_contain_openssl(self, any_url):
        if 'openssl.org' in any_url:
            return any_url
        return ""


    def is_cve_public(self, cve_json):
        try:
            vulnerabilities = cve_json.get("vulnerabilities", [])
            if vulnerabilities:
                vuln_status = vulnerabilities[0].get("cve", {}).get("vulnStatus", "")
                return vuln_status in ["Analyzed", "Modified"]
            return False
        except json.JSONDecodeError:
            print("Error: Invalid JSON")
            return False
    

    def nvd_cve_id_check(self, cve_id):
        # Check if api can return cve_id
        # e.g https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
        headers = {
            "apiKey": f"{self.apiKey}" 
        }
        cve_url = NVD_API_URL + "?cveId=" + cve_id
        response = requests.get(cve_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if not self.is_cve_public(data):
                self.is_cve_public_bool = False
                logger.info(f"CVE ID is not public, Error: {data}")
                return""
            return data
        else:
            logger.info(f"CVE ID does not exist on NVD, Error: {response.status_code}")
            self.is_in_nvd = False
            return ""
        

    def local_dir_check_create(self, FOLDERNAME):
        # Check if current directory has folder named "patches"
        # Create if it does not exist
        curr_dir = os.getcwd()
        target_dir = os.path.join(curr_dir, FOLDERNAME)
        print(target_dir)
        if not os.path.exists(target_dir):
            logger.info("Folder named patches does not exist! Creating...")
            os.makedirs(target_dir)
            logger.info("Folder patches created")
        else:
            logger.info("Folder patches exists")


    def patch_text_getter(self):
        return self.patch_text
    

    def is_in_nvd_getter(self):
        return self.is_in_nvd
    
    
    def is_cve_public_getter(self):
        return self.is_cve_public_bool
    

def parse_arguments():
    parser = argparse.ArgumentParser(description='Takes in cve-id and downloads patch file from NVD website')
    parser.add_argument('-id', '--cve_id', help='CVE ID input')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    inst = Nvd_Patch_Getter(args)
    inst.run()