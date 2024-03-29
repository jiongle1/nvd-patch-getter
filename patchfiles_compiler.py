import json
import shutil
import os

metadata = "result.json"
FINAL_PATCHES_LOC = "/home/scantist_jl/projects/nvd-patch-getter/final_patches"
FOLDERNAME = "final_patches"


def main():
    local_dir_check_create(FOLDERNAME)
    with open(metadata, 'r', encoding="utf-8") as file:
        json_data = json.load(file)

        for dict1 in json_data['result']:
            if dict1["similarity_score"]:
                #ignore html in new patch files
                for file in dict1["new_patch_file"]:
                    with open(file, 'r') as readfile:
                        if "<!DOCTYPE html>" in readfile:
                            pass
                for score in dict1["similarity_score"]:
                    if score > 0.99:
                        #old and new patch are extremely similar, take the old patch
                        copy_old_patch(dict1)
                    elif score < 0.99 and len(dict1["similarity_score"]) == 1:
                        #only 1 new patch is found, and there are some difference,
                        #take the new patch file
                        copy_new_patch(dict1)
                    elif score < 0.99 and len(dict1["similarity_score"]) > 1:
                        #more than 1 new patch is found regardless of the score
                        #submit the file with the highest match
                        max_score_idx = dict1["similarity_score"].index(max(dict1["similarity_score"]))
                        copy_one_new_patch(dict1, max_score_idx)
            else:
                # no patch is found, skip
                pass
                #copy_old_patch(dict1)


def copy_one_new_patch(dict1, max_score_idx):
    filename = dict1["new_patch_file"][max_score_idx]
    id_name = filename.split("/")[-1].split("_")[0]
    patch_filename = FINAL_PATCHES_LOC + '/' + id_name + '.patch'
    shutil.copy(dict1["new_patch_file"][max_score_idx], patch_filename)    


def copy_old_patch(dict1):
    shutil.copy(dict1["prev_patch_file"][0], FINAL_PATCHES_LOC)


def copy_new_patch(dict1):
    old_filename = dict1["new_patch_file"][0]
    id_name = old_filename.split("/")[-1].split("_")[0]
    patch_filename = FINAL_PATCHES_LOC + '/' + id_name + '.patch'
    shutil.copy(dict1["new_patch_file"][0], patch_filename)


def local_dir_check_create(FOLDERNAME):
    # Check if current directory has folder named "patches"
    # Create if it does not exist
    curr_dir = os.getcwd()
    target_dir = os.path.join(curr_dir, FOLDERNAME)
    print(target_dir)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    else:
        pass

if __name__ == "__main__":
    main()