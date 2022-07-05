# Side Channel Attack on AES(SCA)
This repository provides **differential-** and **correlation power analysis(DPA/CPA)** on a single AES round(KeyAdd + non-linear-layer + linear-layer).
The plaintexts and traces should be stored in corresponding files with the correct format(one plaintext/trace per line).
As result, the program will return the most probable key guess (highes difference of means/highest correlation).

For saving the result, the variable _writeFiles_ must be set to 1. This will generate two files, which can then be plotted with a tool of choice.
Example plots are provided.
