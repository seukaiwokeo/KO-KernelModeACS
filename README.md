<img alt="C" src="https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white"/> <img alt="Visual Studio" src="https://img.shields.io/badge/VisualStudio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white"/>

**A simple Kernel Mode Anticheat Project open to developement.**

------------

> **What does it do?**

- Deny user-mode memory access APIs to our process.
- No application can do memory read or write operations on our process.
- There is a list of forbidden drivers, it scan drivers running on the system. It is a bad logic but protects from noobs.

------------

> **How it attach to our process?**

As seen in the code, it checks if there is XCode\XCode.dll in the folder where the processes started from the computer are located and protects the correct ones.
