#!/bin/bash
set -x
uptime

BACK_DIR=/opt/suricata.bak
if [ ! -d ${BACK_DIR} ]; then
  echo "backup dir ${BACK_DIR} is not exist, skip"
  exit 0
fi

#回滚
rm -rf /opt/suricata
mv $BACK_DIR /opt/suricata
if [ $? -ne 0 ]; then
    echo "move ${BACK_DIR} fail, rollback failed"
    exit 1
fi

systemctl daemon-reload
systemctl restart suricata

exit 0
