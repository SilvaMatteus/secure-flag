     _____                           ______ _               ___
    /  ___|                          |  ___| |              \_/
    \ `--.  ___  ___ _   _ _ __ ___  | |_  | | __ _  __ _    |._
     `--. \/ _ \/ __| | | | '__/ _ \ |  _| | |/ _` |/ _` |   |'."-._.-""--.-"-.__.-'/
    /\__/ /  __/ (__| |_| | | |  __/ | |   | | (_| | (_| |   |  \       .-.        (
    \____/ \___|\___|\__,_|_|  \___| \_|   |_|\__,_|\__, |   |   |     (@.@)        )
                                                    __/ |    |   |   '=.|m|.='     /
                                                   |___/     |  /    .='`"``=.    /
    *Test version                                            |.'                 (
                                                             |.-"-.__.-""-.__.-"-.)
                                                             |

A SGX based application to manage flags in a safe way.

## Evaluation and performance of discrete systems

This application is my target project to **Evaluation and performance of discrete systems**, a course of my graduation.

## Instructions to clone the experiment environment

**Note 1:** The steps to run in simulated mode was tested only in Ubuntu 16.04 and 14.04.

**Note 2:** Only processors in [this list](https://github.com/ayeks/SGX-hardware) have SGX support. However, it's possible to run SGX applications in simulated mode in others machines.

To run SGX in Hardware mode, without simulation, follow the steps described [here](https://github.com/01org/linux-sgx).

To run SGX in simulated mode follow these steps:

```shell
git clone https://github.com/01org/linux-sgx.git
cd linux-sgx
sudo apt-get install build-essential ocaml automake autoconf libtool wget python
./download_prebuilt.sh
make sdk_install_pkg
```

You can find the generated Intel(R) SGX SDK installer sgx_linux_x64_sdk_${version}.bin located under linux/installer/bin/, where ${version} refers to the version number.

**Note 3:** It's recommended to install sgxsdk in `/opt/intel` when asked by installer bellow.

```
cd linux/installer/bin
./sgx_linux_x64_sdk_${version}.bin
source ${sgx-sdk-install-path}/environment
```

It's recommended put `source ${sgx-sdk-install-path}/environment` in your `~/.bashrc`.

## How to compile the Secure Flag

There is some combinations to compile the Secure Flag. Using macros you can define which cryptographic algorithm will be used and if the quiet mode will be enable.

The quiet mode is used in the experiments to get the cryptograph result without the ascii art presentation.

**Note:** Only one algorithm should be used to build.

Algorithms available:

- AES_GCM: `AES_GCM=1`

- AES_CTR: `AES_CTR=1`

- To use quiet mode: `QUIET_MODE=1`

**Example:** compiling with AES_CTR and in quiet mode:

`make AES_CTR=1 QUIET_MODE=1`

To clean compiled files:

`make clean`

