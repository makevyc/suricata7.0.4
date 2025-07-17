#!/bin/bash
#功能：升级成功后删除备份文件
set -x
uptime

BACK_DIR=/opt/suricata.bak
if [ -d ${BACK_DIR} ]; then
  rm -rf ${BACK_DIR}
fi

exit 0