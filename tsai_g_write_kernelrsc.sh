#!/bin/sh

KDIR=`pwd`
pushd ../../
sudo ./utils/upgrade_tool di -k $KDIR/kernel.img
sudo ./utils/upgrade_tool di resource $KDIR/resource.img
#This next command is reboot
sudo ./utils/upgrade_tool rd
popd

