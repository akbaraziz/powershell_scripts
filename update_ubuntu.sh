#!/bin/bash

# Need to update and upgrade to get patched up

echo "@@{ub_user_creds}@@" | sudo -S ls

sudo apt-get update -y

sudo apt-get upgrade -y