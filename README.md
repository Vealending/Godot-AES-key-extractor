# Godot AES Key Extractor

## Introduction

The Godot AES Key Extractor is a Python script that uses the LIEF and Capstone libraries to search for potential AES encryption keys in Godot game binary files. 

It searches for `lea` instructions of the form `lea rXX, [rip + disp32]` where `XX` is one of `r12`, `r13`, `r14`, or `r15`, and checks if the address calculated by the `lea` instruction is within the `.data` section of the binary file. 
If it is, a sequence of bytes of length `AES_KEY_SIZE` starting from that address is extracted and checked for null bytes. 
Although AES keys may contain null bytes, removing them significantly reduces the false positive rate.

Doing a detailed disassembly of the `.text` segment can take a while. Expect the script to use between 1 and 3 minutes to complete.

## Compatibility

This script has been tested on Linux and Windows x86_64 binaries compiled using *Godot_v4.0-beta12*.

## Installation

1. Clone the repository to your local machine:

    ```
    git clone https://github.com/Vealending//Godot-AES-key-extractor.git
    ```

2. Install the required Python libraries:

    ```
    pip install lief capstone
    ```

## Usage

1. Edit the `FILE_NAME` variable in the script to point to the binary file you want to analyze.

2. Run the script:

    ```
    python godot_aes_key_extractor.py
    ```

The script will print any potential AES keys it finds. Maybe even some errors. Who knows.

The extracted AES key can be used together with [gdsdecomp](https://github.com/bruvzg/gdsdecomp) for further reverse engineering of the game's asset.

## Acknowledgments

This project was inspired by [godot-key-extract](https://github.com/pozm/godot-key-extract).

# License

This project is licensed under the MIT License. However, it should not be used for malicious purposes. Please :(
