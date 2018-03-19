# nwoythal_aes
Implementation of AES algorithm for CS4920
This is a quick implementation of the AES algorithm. It has no external dependencies, and can be run on anything that has python3.
To run, syntax is as follows:

    python3 nwoythal_aes.py [PLAINTEXT] [KEY] [--debug] [--key_expansion]
    
`--debug` will dump a whole lot of information, it is recommended to use it along with less to properly parse everything.

`--key expansion` will only print the key expansion debug information.
