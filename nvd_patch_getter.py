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


class Nvd_Patch_Getter:

    def __init__(self, args):
        logger.info("Initializing...")
        self.args = args
        self.is_in_nvd = False
        self.is_github_repo = False
        self.is_github_patch = False
        self.is_patch_tag = False
        self.patch_text = ""

    def run(self):
        cve_id = self.args.cve_id
        download = self.args.download
        #local_dir_check_create(FOLDERNAME)
        cve_json = self.nvd_cve_id_check(cve_id)
        if cve_json:
            github_bool = self.github_check(cve_json)
        else:
            pass
        if github_bool:
            cve_patch_link = self.parse_patch(cve_json)
            if cve_patch_link:
                self.patch_text = self.download_cve_patch(cve_patch_link, cve_id, download)
            else:
                logger.info(f"CVE ID: {cve_id} refers to a Github repository, but does not have patch")
                logger.info("Exiting")
                pass
        else:
            logger.info(f"CVE ID: {cve_id} does not refer to a Github repository")
            logger.info("Exiting")
            pass
        

    def download_cve_patch(self, cve_patch_link, cve_id, download):
        # Add a '.patch' to the end of patch URL to download it
        cve_patch_url = cve_patch_link + ".patch"
        response = requests.get(cve_patch_url)
        #filename = "./" + FOLDERNAME + '/' + cve_id + ".patch"
        filename = cve_id + ".patch"

        if response.status_code == 200:
            if download:
                with open(filename, 'w', encoding='utf-8') as file:
                    file.write(response.text)
                logger.info(f"Patch written to {filename}")
            else:
                logger.info(f"Patch not saved, returned as text")
            return response.text
        else:
            logger.info(f"Patch download failed, Error: {response.status_code}")
            return""


    def parse_patch(self, cve_json):
        # get list of references
        list_references = cve_json['vulnerabilities'][0]['cve']['references']
        for reference_dict in list_references:
            # only get patch from github source
            if reference_dict['source'] == "security-advisories@github.com":
                try:
                    for tag_item in reference_dict['tags']:
                        if tag_item == "Patch":
                            patch_url = reference_dict['url']
                            logger.info(f"URL to download patch is: {patch_url}")
                            self.is_github_patch = True
                            return patch_url
                        else:
                            self.is_github_patch = False
                            pass
                except:
                    logger.info(f"Source is from github, but no patch tag is found")
            else:
                pass
            if 'tags' in reference_dict:
                for tag_item in reference_dict['tags']:
                    if tag_item == "Patch":
                        logger.info(f"Patch tag is found, unsure of source")
                        self.is_patch_tag = True
                    else:
                        pass
            else:
                pass
        logger.info(f"Patch is not found")
        return ""


    def github_check(self, cve_json):
        # get sourceIdentifier
        # Github vulnerabilities are from github itself
        sourceIdentifier = cve_json['vulnerabilities'][0]['cve']['sourceIdentifier']
        if sourceIdentifier == "security-advisories@github.com":
            logger.info("CVE ID references to Github")
            self.is_github_repo = True
        else:
            logger.info(f"CVE ID: {cve_json['vulnerabilities'][0]['cve']['id']} does not reference to Github, try another ID")
            self.is_github_repo = False
        return self.is_github_repo


    def nvd_cve_id_check(self, cve_id):
        # Check if api can return cve_id
        # e.g https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
        cve_url = NVD_API_URL + "?cveId=" + cve_id
        response = requests.get(cve_url)

        if response.status_code == 200:
            data = response.json()
            self.is_in_nvd = True
            return data
        else:
            logger.info(f"CVE ID does not exist on NVD, Error: {response.status_code}")
            self.is_in_nvd = False
            return None
        

    def local_dir_check_create(self, FOLDERNAME):
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


    def patch_text_getter(self):
        return self.patch_text
    

    def is_in_nvd_getter(self):
        return self.is_in_nvd
    

    def is_github_repo_getter(self):
        return self.is_github_repo
    

    def is_github_patch_getter(self):
        return self.is_github_patch
    

    def is_patch_tag_getter(self):
        return self.is_patch_tag
    


def parse_arguments():
    parser = argparse.ArgumentParser(description='Takes in cve-id and downloads patch file from NVD website')
    parser.add_argument('-id', '--cve_id', help='CVE ID input')
    parser.add_argument('-d', '--download', action='store_true', help="Include flag for download")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    inst = Nvd_Patch_Getter(args)
    inst.run()