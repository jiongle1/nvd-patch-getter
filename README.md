# nvd-patch-getter
Given CVE_ID, go to NVD website and check if there is a patch available, if yes, download, else return false

command: python3 nvd_patch_getter.py -id CVE-2024-21665

To get model for spacy comparison:

run command: python3 -m spacy download en_core_web_sm
