#! /bin/bash
#set -e
set -x
uptime

PKG_DIR="$(dirname $(readlink -f $(dirname $0)))"
CURRENT_DIR=$(cd `dirname $0`; pwd)
LOGROTATION_DIR=/etc/logrotate.d
suricata_dir=/opt/suricata
interface_config_dir=${suricata_dir}/config
bin_dir=${suricata_dir}/bin
depend_lib_dir=${suricata_dir}/lib
package_script_dir=${suricata_dir}/scripts
config_dir=${suricata_dir}/suricata/config
rules_dir=${suricata_dir}/suricata/rules
log_dir=${suricata_dir}/log
suricata_service_dir=/lib/systemd/system

function InstallLogrotate {
  if [ ! -d ${LOGROTATION_DIR} ]; then
    echo "path does not exist: ${LOGROTATION_DIR}"
    return
  fi

  cat << EOF > ${LOGROTATION_DIR}/suricata
${log_dir}/*.log {
  rotate 30
  missingok
  nocompress
  dateext
  dateformat -%Y-%m-%d-%H-%M
  size 10M
  create
  sharedscripts
  postrotate
      /bin/kill -HUP \`cat ${bin_dir}/suricata.pid 2>/dev/null\` 2>/dev/null || true
  endscript
}

EOF
}

function StopSuricata {
  # 若进程存在，停掉进程
  if [ -f ${suricata_service_dir}/suricata.service ];then
    service suricata stop
  else
    process_count=`ps -ef | grep /opt/suricata/bin/suricata | grep -v grep | wc -l`
    if [ ${process_count} -eq 1 ];then
      ps -ef | grep /opt/suricata/bin/suricata | grep -v grep | awk '{print $2}' | xargs kill -9
    fi
  fi
}

function CreateSuricataDir {
  # 创建进程目录
  #if [ -d ${suricata_dir} ];then
  #  rm -rf ${suricata_dir}
  #fi
  #mkdir -p ${suricata_dir}
  #mkdir -p ${interface_config_dir}
  #mkdir -p ${bin_dir}
  #mkdir -p ${depend_lib_dir}
  #mkdir -p ${package_script_dir}
  #mkdir -p ${config_dir}
  #mkdir -p ${rules_dir}
  mkdir -p ${log_dir}
}

function InstallSuricataFile {
  # 安装网卡配置文件
  cp -f ${CURRENT_DIR}/../config/config.json ${interface_config_dir}/
  cp -f ${CURRENT_DIR}/../config/suricata.ini ${interface_config_dir}/
  dos2unix ${interface_config_dir}/*
  # 安装二进制
  cp -f ${CURRENT_DIR}/../bin/* ${bin_dir}/
  #安装部署相关脚本
  cp -f ${CURRENT_DIR}/* ${package_script_dir}/
  # 安装suricata配置文件
  cp -f ${CURRENT_DIR}/../suricata/config/* ${config_dir}/
  # 安装suricata规则文件
  cp -f ${CURRENT_DIR}/../suricata/rules/* ${rules_dir}/
  # 安装依赖库
  cp -f ${CURRENT_DIR}/../lib/* ${depend_lib_dir}/
}

function InstallLib {
  # 解压python库
  tar xf ${package_script_dir}/ruamel.tar.gz -C ${package_script_dir}
}


function InstallService {
  if [ -f ${suricata_service_dir}/suricata.service ];then
    rm -rf ${suricata_service_dir}/suricata.service
  fi
  cat << EOF > ${suricata_service_dir}/suricata.service
[Unit]
Description=suricata
Wants=network-online.target
After=network.target network-online.target agent-server.service tls-decoder.service
Requires=tls-decoder.service

[Service]
Type=simple
LimitNOFILE=1000000
WorkingDirectory=/opt/suricata
ExecStart=/usr/bin/python3 /opt/suricata/scripts/start.py \$tap_count
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=10
TimeoutStopSec=30
StartLimitInterval=0
StartLimitBurst=100000
Environment="LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/opt/suricata/lib"
EnvironmentFile=/opt/agent-server/.env


[Install]
WantedBy=disable.target

EOF
  systemctl daemon-reload # 生效suricata.service
}

function CopyDir {
  if [ ${PKG_DIR} != ${suricata_dir} ]; then
    rm -rf ${suricata_dir}
    cp -rf ${PKG_DIR} ${suricata_dir}
  fi
  #复制配置模板
  cp -f ${config_dir}/suricata.yaml ${config_dir}/suricata.yaml.template
}

function main {
  #StopSuricata
  CopyDir
  CreateSuricataDir
  #InstallSuricataFile
  InstallLogrotate
  InstallLib
  InstallService
}

main

