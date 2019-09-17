#!/bin/sh

KDIR=`pwd`
sudo '/home/julian/geekbox/rkdeveloptool/rkdeveloptool' wlx kernel ./kernel.img
sudo '/home/julian/geekbox/rkdeveloptool/rkdeveloptool' wlx resource ./resource.img
sudo '/home/julian/geekbox/rkdeveloptool/rkdeveloptool' rd

