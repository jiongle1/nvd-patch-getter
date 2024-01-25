import os
import time
import json

from logger_module import logger
from nvd_patch_getter import parse_arguments as nvd_patch_getter_parser
from nvd_patch_getter import Nvd_Patch_Getter

OLD_PATCH_DIRECTORY = r"/mnt/c/Users/Jiong Le/Downloads/patch_raw_240116"

'''
Flags under nvd_patch_getter.py:
    -id CVE-2024-21665 to download or check a specific cve id
    -d download flag
'''


def main():
    files = old_patch_getter()
    cve_id_list = parse_cve_id(files)
    compare_json_output = compare_patch_file(files, cve_id_list)
    with open('result.json', 'w') as json_file:
        json.dump(compare_json_output, json_file, indent=2)
    
def compare_patch_file(files, cve_id_list):
    compare_json_result = {}
    for index, old_patch_file in enumerate(files):
        old_patch_dir = OLD_PATCH_DIRECTORY + '/' + old_patch_file
        nvd_patch_inst = run_nvd_patch_getter(cve_id_list[index])
        nvd_patch_inst.run()
        time.sleep(6.2)
        compare_json_result[cve_id_list[index]] = {}
        compare_json_result[cve_id_list[index]]['is_in_nvd'] = nvd_patch_inst.is_in_nvd_getter()
        compare_json_result[cve_id_list[index]]['is_github_repo'] = nvd_patch_inst.is_github_repo_getter()
        compare_json_result[cve_id_list[index]]['is_github_patch'] = nvd_patch_inst.is_github_patch_getter()
        compare_json_result[cve_id_list[index]]['is_patch_tag'] = nvd_patch_inst.is_patch_tag_getter()
        with open(old_patch_dir, 'r') as file:
            if file == nvd_patch_inst.patch_text_getter():
                compare_json_result[cve_id_list[index]]['is_same_patch'] = True
            else:
                compare_json_result[cve_id_list[index]]['is_same_patch'] = False
    return compare_json_result
        

def run_nvd_patch_getter(cve_id):
    args = nvd_patch_getter_parser()
    args.cve_id = cve_id
    nvd_patch_getter_main = Nvd_Patch_Getter(args)
    return nvd_patch_getter_main


def parse_cve_id(files_list):
    # extract list of cve_ids from old patch files list
    cve_id_list = [file.split("_")[0] for file in files_list]
    return cve_id_list


def old_patch_getter():
    # get patch from local files, in this case is in location 'downloads'
    # returns list of old patch files
    try: 
        files = os.listdir(OLD_PATCH_DIRECTORY)
        files = [file for file in files if os.path.isfile(os.path.join(OLD_PATCH_DIRECTORY, file))]
        return files
    except OSError as e:
        logger.info(f"Error reading directory: {e}")
        return""
    
if __name__ == "__main__":
    main()