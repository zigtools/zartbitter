#!/bin/bash


dd if=/dev/urandom bs=33 count=1 status=none | base64
