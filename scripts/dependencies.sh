#! /bin/bash
#set -e

function InstallDependcies {
  apt-get -y install libpcre2-dev build-essential autoconf \
  automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
  pkg-config zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make \
  libmagic-dev libjansson-dev rustc cargo jq git-core

  export PATH=$PATH:${HOME}/.cargo/bin
  cargo install --force cbindgen

  # IPS depends
  # apt-get -y install libnetfilter-queue-dev libnetfilter-queue1 \
  # libnfnetlink-dev libnfnetlink0
}

InstallDependcies
