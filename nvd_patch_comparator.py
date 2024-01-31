import os
import time
import json
import spacy

from settings import logger
from nvd_patch_getter import parse_arguments as nvd_patch_getter_parser
from nvd_patch_getter import Nvd_Patch_Getter
from spacy.tokens import Doc


'''
Flags under nvd_patch_getter.py:
    -id CVE-2024-21665 to download or check a specific cve id
    -d download flag
'''


class Nvd_Patch_Comparator:
    def __init__(self):
        logger.info("Start comparator")
        self.old_patch_directory = r"/mnt/c/Users/Jiong Le/Downloads/patch_raw_240116"
        self.new_patch_directory = r"/home/scantist_jl/projects/nvd-patch-getter/patches"
        self.saved_old_patch = r"/home/scantist_jl/projects/nvd-patch-getter/references/old_patch_list.txt"
        self.saved_new_patch = r"/home/scantist_jl/projects/nvd-patch-getter/references/new_patch_list.txt"
        self.download_progress = r"/home/scantist_jl/projects/nvd-patch-getter/references/download_progress.txt"
        self.compare_progress = r"/home/scantist_jl/projects/nvd-patch-getter/references/compare_progress.txt"
        self.json_save_partial = r"/home/scantist_jl/projects/nvd-patch-getter/references/result.json.txt"
        self.compare_json_result = {"result": []}


    def run(self):
        old_files_list = self.old_patch_getter()
        cve_id_list = self.parse_cve_id(old_files_list)
        self.save_file(self.saved_old_patch, cve_id_list)
        self.download_all_patches(cve_id_list)
        new_files_list = self.new_patch_getter()
        compare_json_output = self.compare_patch_file(old_files_list, new_files_list)
        with open('result.json', 'w') as json_file:
            json.dump(compare_json_output, json_file, indent=2)


    def download_all_patches(self, cve_id_list):
        saved_list = self.check_download_progress()
        if saved_list:
            #remove saved_list items from cve_id_list and continue progress
            cve_id_list = [item for item in cve_id_list if item not in saved_list]
        for cve_id in cve_id_list:
            nvd_patch_inst = self.run_nvd_patch_getter(cve_id)
            nvd_patch_inst.run()
            self.save_file(self.download_progress, [cve_id])
            time.sleep(1.7)


    def check_download_progress(self):
        return self.read_file(self.download_progress)
        
        
    def compare_patch_file(self, old_files_list, new_filename_list):
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
        compared_list = self.check_compared_progress()
        if compared_list:
            #remove saved_list items from cve_id_list and continue progress
            old_files_list = [item for item in old_files_list if item not in compared_list]
            #append all previous results to self.json_compare_result
            with open(self.json_save_partial, 'r') as file:
                self.compare_json_result["result"].append(line.strip() for line in file)
        # it is a list of <directory> + <filename>
        for old_index, old_file in enumerate(old_files_list):
            self.compare_details = {
                "cve_id": "",
                "prev_patch_file": [],
                "new_patch_file": [],
                "similarity_score": [],
                "file_match": ""
            }
            self.compare_details['cve_id'] = self.parse_one_cve_id(old_file)
            self.compare_details["prev_patch_file"].append(old_file)
            logger.info(f"Index of current file is {old_index}")
            for new_patch_file in new_filename_list:
                if self.compare_details['cve_id'] in new_patch_file:
                    new_patch_dir = self.new_patch_directory + '/' + new_patch_file
                    old_patch_dir = self.old_patch_directory + '/' + old_file
                    self.compare_details["new_patch_file"].append(new_patch_dir)
                    with open(old_patch_dir, 'r') as oldfile1:
                        oldcontent = oldfile1.read()
                        with open(new_patch_dir, 'r') as newfile1:
                            newcontent = newfile1.read()
                            if "<!DOCTYPE" in newcontent:
                                logger.info(f"HTML found in document")
                                logger.info(f"CVE ID: {self.compare_details['cve_id']}")
                                pass
                            else:
                                logger.info(f"Compare {old_patch_dir} and {new_patch_dir}")
                                similarity_score = self.semantic_file_comparator(oldcontent, newcontent)
                                self.compare_details["similarity_score"].append(similarity_score)
                                if similarity_score > 0.99:
                                    logger.info(f"Similarity of old patch and new patch is: {similarity_score}, it is viewed as the same")
                                    self.compare_details["file_match"] = old_patch_dir
                                else:
                                    logger.info(f"Similarity of old patch and new patch is: {similarity_score}, recommended to take new patch")
                                    self.compare_details["file_match"] = new_patch_dir
                else:
                    pass
            self.save_file(self.compare_progress, [old_file])
            self.save_file(self.json_save_partial, [str(self.compare_details)])
            self.compare_json_result["result"].append(self.compare_details)
        return self.compare_json_result


    def check_compared_progress(self):
        return self.read_file(self.compare_progress)


    def semantic_file_comparator(self, oldcontent, newcontent):
        # uses semantic comparison, files are considered the same if more than 90% match
        max_length = max(len(oldcontent), len(newcontent))

        processed_oldfile = self.process_file(oldcontent, max_length)
        processed_newfile = self.process_file(newcontent, max_length)

        # Calculate semantic similarity using spaCy's similarity method
        similarity_score = processed_oldfile.similarity(processed_newfile)
        return similarity_score


    def process_file(self, content, max_length):
        paragraphs = content.split("\n")
        nlp = spacy.load("en_core_web_sm")
        nlp.max_length = max_length

        docs = list(nlp.pipe(paragraphs))
        c_doc = Doc.from_docs(docs)
        return c_doc


    def run_nvd_patch_getter(self, cve_id):
        args = nvd_patch_getter_parser()
        args.cve_id = cve_id
        nvd_patch_getter_main = Nvd_Patch_Getter(args)
        return nvd_patch_getter_main


    def parse_cve_id(self, files_list):
        '''
        returns a list
        '''
        # extract list of cve_ids from old patch files list
        cve_id_list = [file.split("_")[0] for file in files_list]
        return cve_id_list
    

    def parse_one_cve_id(self, oldfilename):
        '''
        returns a string
        '''
        # extract one cve_id from filename
        cve_id = oldfilename.split("_")[0]
        return cve_id
    

    def old_patch_getter(self):
        # get patch from local files, in this case is in location 'downloads'
        # returns list of old patch files
        try: 
            files = os.listdir(self.old_patch_directory)
            files = [file for file in files if os.path.isfile(os.path.join(self.old_patch_directory, file))]
            return files
        except OSError as e:
            logger.info(f"Error reading old patch directory: {e}")
            return""
        
    def new_patch_getter(self):
        # get patch from local files, in this case <current_dir>/patches
        # returns list of new patch files
        try: 
            files = os.listdir(self.new_patch_directory)
            files = [file for file in files if os.path.isfile(os.path.join(self.new_patch_directory, file))]
            return files
        except OSError as e:
            logger.info(f"Error reading new patch directory: {e}")
            return""
        
    def save_file(self, filename, file_list):
        '''
        Write list to file
        '''
        file_loc = '/' + os.path.join(*filename.split('/')[:-1])
        # Create the folder if it does not exist
        if not os.path.exists(file_loc):
            os.makedirs(file_loc)
            logger.info(f"Folder '{file_loc}' created.")
        # Create the file if it does not exist
        if not os.path.exists(filename):
            with open(filename, 'w') as file:
                for item in file_list:
                    file.write(f"{item}\n")
            logger.info(f"File '{filename}' created.")
        else:
            # if exist, append to it
            with open(filename, 'r') as file:
                line_count = sum(1 for line in file)
                if len(file_list) > 1 and line_count == len(file_list):
                    #same length no need for change
                    logger.info(f"File '{filename}' is same as length of list, there is no appending.")
                    return
            with open(filename, 'a') as file:
                for item in file_list:
                    file.write(f"{item}\n")
            logger.info(f"File '{filename}' rewritten.")


    def read_file(self, filename):
        my_list=[]
        try:
            with open(filename, 'r') as file:
                my_list = [line.strip() for line in file]
        except:
            file_loc = '/' + os.path.join(*filename.split('/')[:-1])
            if not os.path.exists(file_loc):
                os.makedirs(file_loc)
                logger.info(f"Folder '{file_loc}' created.")
            # Create the file if it does not exist
            if not os.path.exists(filename):
                with open(filename, 'w') as file:
                    pass
                logger.info(f"File '{filename}' created.")
        return my_list


if __name__ == "__main__":
    inst = Nvd_Patch_Comparator()
    inst.run()