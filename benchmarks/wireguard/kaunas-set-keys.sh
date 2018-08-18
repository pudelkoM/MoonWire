#!/bin/bash

set -e
set -x

ssh omanyte "ssh-keygen -q -t ed25519 -f /root/.ssh/id_ed25519 -N ''"
ssh omastar "ssh-keygen -q -t ed25519 -f /root/.ssh/id_ed25519 -N ''"

omanyte_key=$(ssh omanyte "cat /root/.ssh/id_ed25519.pub")
omastar_key=$(ssh omastar "cat /root/.ssh/id_ed25519.pub")

ssh omanyte "echo $omastar_key >> /root/.ssh/authorized_keys"
ssh omastar "echo $omanyte_key >> /root/.ssh/authorized_keys"
