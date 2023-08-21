# NXP SE050 Secure Element Provisioning app for Windows 11

This repository enables the utilization of the NXP SE050 Secure Element on Windows 11. The SE050 is interfaced using the FTDI FT260 to convert it to a USB accessible device. This app sets up the SE050 to generating self-signed certificate and stores the certificate on the SE050. The certificate is then used to sign and verify data.

The app is written in C++ and uses the Plug and Trust Middleware from NXP. The Plug and Trust Middleware is a software stack that enables the secure communication between a host and a secure element. The host and secure element are connected via a USB cable. The Plug and Trust Middleware is used to communicate with the secure element and perform the following operations:

- Generate ECC 256 key pair.
- Generate a self-signed certificate and store it into SE050.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

- Seamless integration with Windows 11.
- USB conversion using FTDI FT260.
- Generate ECC 256 key pair for testing.
- Generate a self-signed certificate using generated private key.

## Installation

1. **Prerequisites**:
    - Windows 11 operating system.
    - Visual Studio 2022.
    - place Plug ant Trust Middleware 04.03.01 from official NXP website as unzipped simw-top folder.
    - NXP SE050C1 with FTDI FT260 USB-HID converter. [USB TO I2C CLICK](https://www.mikroe.com/usb-to-i2c-click) is available in COTS products.
    - [FireDaemon OpenSSL 3](https://download.firedaemon.com/FireDaemon-OpenSSL/FireDaemon-OpenSSL-x64-3.1.2.exe)

2. **Compiling**:
    - Download the latest release from the [GitHub](https://github.com/kmwebnet/se050-windows-provisioning-app).
    - Unzip and place the Plug and Trust MIddleware in this directory.
    - Build on Visual Studio 2022. upon success, compiled app named se050provisioning.exe will be generated on build\x64.
    
## Usage

- Execute se050provisioning.exe.
- Make sure se050provisioning.exe and LibFT260.dll are in the same directory as the executable.
- Tested applications: [PuTTY CAC](github.com/NoMoreFood/putty-cac/releases) with [kmwebnet/se050-windows-pkcs11-lib](https://github.com/kmwebnet/se050-windows-pkcs11-lib).

# Sample output

- By using Plug and Trust Middleware, the SE050 generates a keypair with ObjectID 0x7DC00001.
- Self-signed certificate is generated and stored on the SE050 with ObjectID 0x7DC00002.
- Refer about pre setting key and cert: [SE050 Configurations](https://www.nxp.jp/docs/en/application-note/AN12436.pdf)

```powershell

App   :INFO :Using default PlatfSCP03 keys. You can use keys from file using ENV=EX_SSS_BOOT_SCP03_PATH
smCom :WARN :Previous transaction buffer is now cleard
sss   :INFO :atr (Len=35)
      00 A0 00 00    03 96 04 03    E8 00 FE 02    0B 03 E8 08
      01 00 00 00    00 64 00 00    0A 4A 43 4F    50 34 20 41
      54 50 4F
App   :INFO :Success
App   :INFO :sss_key_store_get_key status 5a5a5a5a
App   :INFO :len = 254
App   :INFO :cert (Len=345)
      30 82 01 55    30 81 FB A0    03 02 01 02    02 01 01 30
      0C 06 08 2A    86 48 CE 3D    04 03 02 05    00 30 17 31
.....
      DB FC D4 FD    CE 96 01 3F    FD 9D A2 5A    8C 64 F8 79
      F7 B5 22 4C    0F 04 70 24    3A
App   :INFO :Success

<your path>se050provisioning.exe (プロセス 20628) は、コード 0 で終了しました。
このウィンドウを閉じるには、任意のキーを押してください...

```

## License
This project is licensed under the Apache 2.0 License unless stated otherwise.

## Disclaimer
This project is not affiliated with NXP in any way. This software is for verification purposes only. The authors or maintainers are not responsible for any damages or losses incurred from its use in commercial or critical systems.
