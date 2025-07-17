#! /bin/bash
# set -e
set -x
uptime

suricata_dir=/opt/suricata
suricata_service=/lib/systemd/system/suricata.service
SURICATA_LOGROTATE=/etc/logrotate.d/suricata

function StopSuricata {
  # 停掉进程
  # 若进程存在，停掉进程
  if [ -f ${suricata_service} ];then
    service suricata stop
  else
    process_count=`ps -ef | grep /opt/suricata/bin/suricata | grep -v grep | wc -l`
    if [ ${process_count} -eq 1 ];then
      ps -ef | grep /opt/suricata/bin/suricata | grep -v grep | awk '{print $2}' | xargs kill -9
    fi
  fi
  # 删除运行目录
  rm -rf ${suricata_dir}
  # 删除service
  rm -rf ${suricata_service}
  systemctl daemon-reload
}

StopSuricata
# 删除logrotate配置文件
rm -f ${SURICATA_LOGROTATE}