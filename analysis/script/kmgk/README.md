This directory contains the Keymaster and Gatekeeper TA for Keystore benchmark.


Structure of the directory
- raw_files: raw C program files from https://github.com/linaro-swg/kmgk
  - gatekeeper_ta.c: file containing C program for Gatekeeper TA
  - keystore_ta.c, auth.c: files containing C program for Keymaster TA
- preprocessed_files
  - gatekeeper/keymaster_ta.c: C files that are annotated and merged with relevant header files, ready for translation
  - gk/km_custom_main.txt: files containing custom main functions for the Gatekeeper and Keymaster TA