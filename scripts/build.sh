#! /bin/bash

SCRIPT_DIR=$(cd `dirname $0`; pwd)
SRC_DIR=${SCRIPT_DIR}/../
export PATH=$PATH:${HOME}/.cargo/bin

function BuildSuricata {
  pushd libhtp
  git checkout 0.5.x
  popd

  pushd ${SRC_DIR}
  # bundled Libhtp and suricata-update
  ./scripts/bundle.sh
  ./autogen.sh

  # configuration
  # 二进制路径   /usr/bin/suricata
  # 配置文件路径 /etc/suricata/suricata.yaml
  # 规则文件路径 /var/lib/suricata/rules
  clangbin=`which clang-9`
  ./configure --disable-gccmarch-native --enable-debug --prefix=/usr/ --sysconfdir=/etc --localstatedir=/var --enable-lua --enable-ebpf --enable-ebpf-build --with-clang=$clangbin #--enable-geoip --enable-dpdk

  # compile
  make -j4
  # make install-conf
  #make install-rules
  make install-full
  popd
  # ldconfig
}

BuildSuricata




