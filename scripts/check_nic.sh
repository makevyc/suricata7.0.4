#!/bin/bash
# 功能: 检查网卡状态，启用未启动的网卡
# 需要root用户执行

NIC_NAME="$1"  # 指定的网卡名称

# 检查网卡是否存在
if ip link show $NIC_NAME > /dev/null 2>&1; then
    # 检查网卡状态
    if ip link show $NIC_NAME | grep -q "state UP"; then
        echo "nic $NIC_NAME is up state"
    else
        echo "nic $NIC_NAME is down state, set up..."
        ip link set $NIC_NAME up
    fi
else
    echo "nic $NIC_NAME is not exist"
fi
