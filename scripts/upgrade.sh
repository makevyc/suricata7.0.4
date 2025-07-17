#!/bin/bash
source /opt/public/.util/.util.sh
import_env_helper

set -x
uptime

# 配置文件从1.0.0转换为1.0.1
# 1.0.0最初版本 rule: 空表示全采集
# 1.0.1版本 rule: "all"表示全采集 空表示全部不采集
function convert_1.0.0_1.0.1() {
  local config_path=$1
  old_rule=$(grep '"rule":' $config_path | cut -d'"' -f4)
  old_rule=`echo $old_rule| xargs` # trim

  #1.0.0的""替换为"all"
  if [ -z "$old_rule" ]; then
    new_rule="all"
  else
    return 0
  fi

  echo "old_rule=$old_rule,new_rule=$new_rule"
  # 注意$new_rule里不能出现斜杠
  sed -i 's/"rule": "[^"]*"/"rule": "'"$new_rule"'"/' $config_path || { echo "配置修改失败"; return 1; }
  return 0
}


# 配置转换
function config_convert() {
  local config_path=$1
  local old_version=$2
  local new_version=$3

  if [ $old_version == $new_version ]; then
    #相同版本 无需转换
    echo "same version: $old_version"
    return 0
  fi

  convert_func="convert_${old_version}_${new_version}"
  # 判断函数是否存在
  if type $convert_func &> /dev/null; then
      echo "exec $convert_func"
      $convert_func $config_path
      return $?
  else
      echo "can not found $convert_func"
  fi

  return 0
}

# 配置文件处理
function config_handle() {
  local new_config_path=$1
  local new_suricata_ini_path=$2
  local old_config_path="/opt/suricata/config/config.json"
  local old_suricata_ini_path="/opt/suricata/config/suricata.ini"

  # 复制旧配置文件
  cp "$old_config_path" "$new_config_path" || { echo "文件复制失败"; return 1; }
  
  # 配置文件转换
  old_ver=$(grep -Po '(?<=config_version=)\w+.*' $old_suricata_ini_path || echo "1.0.0")
  new_ver=$(grep -Po '(?<=config_version=)\w+.*' $new_suricata_ini_path || echo "1.0.0")
  config_convert $new_config_path $old_ver $new_ver || { echo "配置转换失败"; return 2; }
  
  return 0
}

# 升级函数 
function upgrade() {
    date
    echo "start upgrade"
    local source_dir=$(realpath "$(dirname "$0")/../")
    if [ ! -d "$source_dir" ]; then
        echo "source dir $source_dir is not exist"
        return $EXIT_FS_ERR
    fi

    is_enable=$(systemctl is-enabled suricata)
    is_active=$(systemctl is-active suricata)

    local new_config_path="$source_dir/config/config.json"
    local new_suricata_ini_path="$source_dir/config/suricata.ini"
    local new_custom_path="$source_dir/config/custom.json"

    # 配置转换
    # config_handle $new_config_path $new_suricata_ini_path || { echo "配置处理异常"; return $EXIT_ERR; }
    cp -f /opt/suricata/config/config.json ${new_config_path}
    if [ -e "/opt/suricata/config/custom.json" ]; then
      cp -f /opt/suricata/config/custom.json ${new_custom_path}
    fi

    # 备份
    rm -rf /opt/suricata.bak
    # 日志文件最多只保留3个
    ls -t /opt/suricata/log/stats.log-* | tail -n +4 | xargs rm -- || true
    cp -rf /opt/suricata /opt/suricata.bak
    if [ $? -ne 0 ]; then
        echo "suricata backup failed"
        return $EXIT_FS_ERR
    fi

    # 升级
    systemctl stop suricata
    rm -rf /opt/suricata/lib/*
    cp -rf "$source_dir" /opt/
    /opt/suricata/scripts/install.sh
    if [ $? -ne 0 ]; then
        echo "upgrade suricata fail"
        
        return $EXIT_FS_ERR
    fi

    # 启动服务
    if [ $is_enable == "enabled" ]; then
      systemctl enable suricata
    fi

    systemctl start suricata

    date
    echo "upgrade success"
    return 0
}

upgrade >> /tmp/suricata.upgrade.log 2>&1
exit_code=$?
cp -f /tmp/suricata.upgrade.log /opt/suricata/

if [ $exit_code -ne 0 ]; then 
    cp -f /tmp/suricata.upgrade.log /opt/suricata.bak/
fi

exit ${exit_code}
