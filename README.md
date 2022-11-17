# PyIPTools
> Archived project pre 2018, est 2018

This project keeps track of which domains are being blocked by pihole by your device.

## Getting started
This project uses [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers). Make sure to have [docker](https://docker.com/) installed. 

To run this code, reopen this folder in its dev container and press F5 to debug.

# About this project
I wrote this project to see which domain names were looked up and connected with while using a raspberry pi. For educational purposes I wrote and interpreted DNS data structs myself. This project uses docker-compose in conjunction with pihole which blocks requests to certain domains. 

Sample of a successful run:
![A table containing DNS domain, block status and last updated timestamp](/.doc/testrun.png)