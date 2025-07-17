#! /bin/bash
set -ex

PROJ_SCRIPTS_DIR=$(cd `dirname $0`; pwd)
SRC_DIR=${PROJ_SCRIPTS_DIR}/../
PACKAGE_DIR=${SRC_DIR}/package
EBPF_DIR=${SRC_DIR}/ebpf

version=`gv`
os="linux"
arch="amd64"
if uname -m | grep -q "aarch"; then
  arch="arm64"
fi
TARGET=suricata-$version-$os-$arch.tar.gz

# 临时目录创建
function CreateTmpDir {
  tmp_dir=$(mktemp -d)
  suricata_dir=${tmp_dir}/suricata
  interface_config_dir=${suricata_dir}/config
  bin_dir=${suricata_dir}/bin
  depend_lib_dir=${suricata_dir}/lib
  package_scripts_dir=${suricata_dir}/scripts
  config_dir=${suricata_dir}/suricata/config
  rules_dir=${suricata_dir}/suricata/rules
  log_dir=${suricata_dir}/log
  mkdir -p ${interface_config_dir}
  mkdir -p ${bin_dir}
  mkdir -p ${depend_lib_dir}
  mkdir -p ${package_scripts_dir}
  mkdir -p ${config_dir}
  mkdir -p ${rules_dir}
  mkdir -p ${log_dir}
}

function PreparePackageFile {
  # 拷贝网卡配置文件
  cp -f ${SRC_DIR}/config/config.json ${interface_config_dir}/
  cp -f ${SRC_DIR}/config/suricata.ini ${interface_config_dir}/
  cp -f ${SRC_DIR}/config/custom.json ${interface_config_dir}/
  # 拷贝二进制
  strip /usr/bin/suricata
  cp -f /usr/bin/suricata ${bin_dir}/
  cp -f ${EBPF_DIR}/sr_filter.bpf ${bin_dir}/
  cp -f ${EBPF_DIR}/vxlan_lb.bpf ${bin_dir}/
  cp -f ${EBPF_DIR}/sr_lb.bpf ${bin_dir}/
  cp -f ${EBPF_DIR}/lb.bpf ${bin_dir}/

  if [ "$arch" == "arm64" ]; then
    cp -f ${EBPF_DIR}/bpftool_arm ${bin_dir}/bpftool
  else
    cp -f ${EBPF_DIR}/bpftool_x86 ${bin_dir}/bpftool
  fi

  chmod +x ${bin_dir}/*
  # 拷贝suricata依赖库文件
  cp -f /usr/lib/libhtp.so.2.0.0 ${depend_lib_dir}/libhtp.so.2
  set +e
  cp $(ldd /usr/bin/suricata | grep libjansson | awk '{print $3}') ${depend_lib_dir}
  cp $(ldd /usr/bin/suricata | grep liblua | awk '{print $3}') ${depend_lib_dir}
  cp $(ldd /usr/bin/suricata | grep libnet | awk '{print $3}') ${depend_lib_dir}
  cp $(ldd /usr/bin/suricata | grep libbpf | awk '{print $3}') ${depend_lib_dir}
  cp $(ldd /usr/bin/suricata | grep libunwind | awk '{print $3}') ${depend_lib_dir}
  set -e

  # 拷贝进程启动、安装、卸载脚本
  cp -f ${PROJ_SCRIPTS_DIR}/start.py ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/install.sh ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/uninstall.sh ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/check_nic.sh ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/upgrade.sh ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/commit.sh ${package_scripts_dir}/
  cp -f ${PROJ_SCRIPTS_DIR}/rollback.sh ${package_scripts_dir}/
  chmod +x ${package_scripts_dir}/*.sh

  # 拷贝配置文件
  cp -f /etc/suricata/* ${config_dir}/
  cp -f ${SRC_DIR}/config/suricata.yaml ${config_dir}/
  cp -f ${SRC_DIR}/config/able.json ${suricata_dir}

  # able的版本号每次打包都要更新 不然不会执行升级脚本
  ver=`git rev-parse --short HEAD`
  sed -i "s/commitid/${ver}/g" ${suricata_dir}/able.json

  # 拷贝规则文件
  # cp -f /var/lib/suricata/rules/*.rules ${rules_dir}/
  #cp -f ${SRC_DIR}/shrino_rules/http.rules ${rules_dir}/
  cp -f ${SRC_DIR}/shrino_rules/* ${rules_dir}/

  # 拷贝python库
  cp -f ${PROJ_SCRIPTS_DIR}/ruamel.tar.gz ${package_scripts_dir}/
}

function CreatePackage {
  # 打包
  rm -rf ${PACKAGE_DIR}
  mkdir -p ${PACKAGE_DIR}
  cd ${tmp_dir}
  tar -zcvf ${PACKAGE_DIR}/${TARGET} suricata
}

function RestoreEnvionment {
  # 删除临时目录
  cd -
  rm -rf ${tmp_dir}
  # make install目录删除，还原编译环境
  # 删除二进制
  rm -rf /usr/bin/suricata
  # 删除配置文件
  rm -rf /etc/suricata
  # 删除规则规则文件
  rm -rf /var/lib/suricata
}

function main {
  CreateTmpDir
  PreparePackageFile
  CreatePackage
  #RestoreEnvionment
}

main

