import os
import time
import json
import spacy

from settings import logger
from nvd_patch_getter import parse_arguments as nvd_patch_getter_parser
from nvd_patch_getter import Nvd_Patch_Getter

OLD_PATCH_DIRECTORY = r"/mnt/c/Users/Jiong Le/Downloads/patch_raw_240116"
NEW_PATCH_DIRECTORY = r"/home/scantist_jl/projects/nvd-patch-getter/patches"

'''
Flags under nvd_patch_getter.py:
    -id CVE-2024-21665 to download or check a specific cve id
    -d download flag
'''


def main():
    old_files = old_patch_getter()
    cve_id_list = parse_cve_id(old_files)
    download_all_patches(cve_id_list[0:7])
    new_files = new_patch_getter()
    compare_json_output = compare_patch_file(old_files[0:7], new_files[0:7], cve_id_list[0:7])
    with open('result.json', 'w') as json_file:
        json.dump(compare_json_output, json_file, indent=2)


def download_all_patches(cve_id_list):
    for cve_id in cve_id_list:
        nvd_patch_inst = run_nvd_patch_getter(cve_id)
        nvd_patch_inst.run()
        time.sleep(1.7)

    
def compare_patch_file(old_files, new_files, cve_id_list):
    '''
    sample json output: 
    {
        "result": 
            [
                {
                    "cve_id": "CVE-2024-21665",
                    "prev_patch_file": ["directory to OLD patch file"],
                    "new_patch_file": ["directory to NEW patch file", "directory to NEW patch file"],
                    "similarity_score": ["score1", "score2"]
                    "file_match": "directory to NEW patch file" or "" (meaning none of the new patches matches with old patch file)
                },
                {
                    "cve_id": "CVE-2024-21666"
                    ...
                },
            ]
    }
    '''
    compare_json_result = {}
    compare_json_result["result"] = []
    for old_index, old_patch_file in enumerate(old_files):
        old_patch_dir = OLD_PATCH_DIRECTORY + '/' + old_patch_file
        cve_dict_details = {}
        cve_id = cve_id_list[old_index]
        cve_dict_details["cve_id"] = cve_id
        cve_dict_details["prev_patch_file"] = []
        cve_dict_details["prev_patch_file"].append(old_patch_dir)
        cve_dict_details["new_patch_file"] = []
        cve_dict_details["similarity_score"] = []
        cve_dict_details["file_match"] = ""
        for new_index, new_patch_file in enumerate(new_files):
            if cve_id in new_patch_file:
                new_patch_dir = NEW_PATCH_DIRECTORY + '/' + new_patch_file
                cve_dict_details["new_patch_file"].append(new_patch_dir)
                with open(old_patch_dir, 'r') as oldfile1:
                    oldcontent = oldfile1.read()
                    with open(new_patch_dir, 'r') as newfile1:
                        newcontent = newfile1.read()
                        logger.info(f"Compare {old_patch_dir} and {new_patch_dir}")
                        similarity_score = semantic_file_comparator(oldcontent, newcontent)
                        cve_dict_details["similarity_score"].append(similarity_score)
                        if similarity_score > 0.99:
                            logger.info(f"Similarity of old patch and new patch is: {similarity_score}, it is viewed as the same")
                            cve_dict_details["file_match"] = old_patch_dir
                        else:
                            logger.info(f"Similarity of old patch and new patch is: {similarity_score}, recommended to take new patch")
                            cve_dict_details["file_match"] = new_patch_dir

        compare_json_result["result"].append(cve_dict_details)
    return compare_json_result


def semantic_file_comparator(oldcontent, newcontent):
    # uses semantic comparison, files are considered the same if more than 90% match
    nlp = spacy.load("en_core_web_sm")
    doc1 = nlp(oldcontent)
    doc2 = nlp(newcontent)

    # Calculate semantic similarity using spaCy's similarity method
    similarity_score = doc1.similarity(doc2)
    return similarity_score



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
        logger.info(f"Error reading old patch directory: {e}")
        return""
    
def new_patch_getter():
    # get patch from local files, in this case <current_dir>/patches
    # returns list of new patch files
    try: 
        files = os.listdir(NEW_PATCH_DIRECTORY)
        files = [file for file in files if os.path.isfile(os.path.join(NEW_PATCH_DIRECTORY, file))]
        return files
    except OSError as e:
        logger.info(f"Error reading new patch directory: {e}")
        return""
    
if __name__ == "__main__":
    main()