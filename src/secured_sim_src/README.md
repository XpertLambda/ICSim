# Barbhack 2024 - Car Hacking Workshop

This repository contains the various material for the 2024 edition of [Barbhack](https://www.barbhack.fr), the french southernmost hacking event. 

The purpose of this workshop is to teach some basics on Car Hacking :

- Discovering the CAN bus
- Getting some entry tips on how to reverse an ECU
- Having fun with TPMS signals

## CAN bus hands-on

To discover the CAN bus, this repo holds a fork of "Instrument Cluster Simulator for SocketCAN" aka **ICSim** : https://github.com/zombieCraig/ICSim

It extends the basic ICSim with some specific features :
* Some controls are not related to a CAN frame, to simulate sensors/actuators on ECU
* A very basic diag tool is simulated to help understanding UDS protocol
* A few OBD-II and UDS commands are supported
* To learn with fun, a scoring system with few challenges has been implemented

![Main UI](https://raw.githubusercontent.com/phil-eqtech/CH-Workshop/master/media/interface.png)
![Controls](https://raw.githubusercontent.com/phil-eqtech/CH-Workshop/master/media/controls.png)

If you are not running on Linux or you don't want to compile the application, a virtual machine (1.1Gb) is available here : https://mega.nz/file/YbRylYBZ#KMW4zd3JmxnkbZCmlqBhkwpty-k6-tacLpci9MnZRms
Login : barbhack - password : 12345678

## ECU reverse engineering tips

The provided firmware is from a Tricore TC166 microcontroller

The aim is to:

- Find the UDS database using [binbloom](https://github.com/quarkslab/binbloom)
- Identify UDS Negative Response Code in those functions
- Locate the DataIdentifier database and understand its structure

## TPMS signals

We provide an RF capture of a Tire Pressure Monitoring System, to analyse using [rtl_433](https://github.com/merbanan/rtl_433) or [Univeral Radio Hacker](https://github.com/jopohl/urh) its content, in order to spoof it.