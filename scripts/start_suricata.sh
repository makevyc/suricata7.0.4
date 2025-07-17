#! /bin/bash
#set -e

suricata_dir=/opt/suricata
bin_dir=${suricata_dir}/bin
config_dir=${suricata_dir}/suricata/config
lib_dir=${suricata_dir}/lib
interface_cmd=""
interface_arr=("eth0")

for interface in "${interface_arr[@]}"; do
    interface_cmd+=" -i $interface"
done

virtual_interface="agent-tap0"
if ip link show ${virtual_interface} &> /dev/null; then
    interface_cmd+=" -i agent-tap0"
fi

#export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/suricata/lib
process_count=`ps -ef | grep /opt/suricata/bin/suricata | grep -v grep | wc -l`
if [ ${process_count} -eq 0 ];then
  ${bin_dir}/suricata -c ${config_dir}/suricata.yaml ${interface_cmd} -k none #-D
fi
