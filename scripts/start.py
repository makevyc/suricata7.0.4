# -*- coding: utf-8 -*-
# suricata启动脚本
# 
import os
import sys
import subprocess
import math
import json
import socket
import logging
import time
import ipaddress
import unittest
import struct
import threading
import copy
from collections import deque
from logging.handlers import RotatingFileHandler
# 优先导入ruamel 
try:
    from ruamel.yaml import YAML
except ImportError:
    print("import ruamel.yaml error")
    # try:
    #     import yaml
    # except ImportError:
    #     raise ImportError("can not import yaml.")

# 设置变量
suricata_dir = '/opt/suricata'
bin_dir = os.path.join(suricata_dir, 'bin')
config_dir = os.path.join(suricata_dir, 'suricata/config')
lib_dir = os.path.join(suricata_dir, 'lib')
config_json_file=os.path.join(suricata_dir, 'config/config.json')
custom_json_file=os.path.join(suricata_dir, 'config/custom.json')
suricata_yaml_file = os.path.join(suricata_dir, 'suricata/config/suricata.yaml')
suricata_yaml_template = os.path.join(suricata_dir, 'suricata/config/suricata.yaml.template')
log_file = os.path.join(suricata_dir, "log/start.log")
need_capture = True  # 是否需要指定业务网口进行抓包
use_ebpf = False     # 是否使用ebpf作为过滤
sr_filter_ebpf = "/opt/suricata/bin/sr_filter.bpf"
vxlan_lb_ebpf = "/opt/suricata/bin/vxlan_lb.bpf"
sr_lb_ebpf = "/opt/suricata/bin/sr_lb.bpf"
bpftool = "/opt/suricata/bin/bpftool"
contain_all = False  # 是否包含"0.0.0.0/0"这种全网段
tap_count = 4        # tap网卡数量

# init
def init_log():
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=2)
    formatter = logging.Formatter('%(levelname)s: %(asctime)s %(filename)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def run_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, text=True, check=True, shell=True)
        if result.stderr:
            logging.warning("run %s, err: %s", command, result.stderr)

        return result.returncode
    except subprocess.CalledProcessError as e:
        logging.warning("run %s, err: %s", command, e)
        return -1

# 读取配置
def read_config(json_file):
    config_data = {}
    try:
        with open(json_file, 'r') as file:
            logging.info(file.read())
            file.seek(0)
            config_data = json.load(file)
    except Exception as e:
        logging.error("read_config exception,type={},content={}".format(repr(e), e))

    return config_data

# uint32转bytes
def uint_to_4bytes(number):
    # 使用 struct.pack 将整数转换为 4 个字节
    # 'I' 表示无符号整数（4 字节）
    byte_array = struct.pack('<I', number)
    return ' '.join(f'0x{b:02x}' for b in byte_array)

def uint_to_2bytes(number):
    # 使用 struct.pack 将整数转换为 2 个字节
    # 'H' 表示无符号整数（2 字节）
    byte_array = struct.pack('<H', number)
    return ' '.join(f'0x{b:02x}' for b in byte_array)

# ipv4转bytes 
def ipv4_to_bytes(ipv4_str):
    byte_array = socket.inet_aton(ipv4_str)
    return ' '.join(f'0x{b:02x}' for b in byte_array) # 大端
    # ip_int = struct.unpack('!I', byte_array)[0]  # big endian
    # little_endian_bytes = struct.pack('<I', ip_int)  # little endian bytes
    # return ' '.join(f'0x{b:02x}' for b in little_endian_bytes) # 小端

# 设置epbf过滤条件
def set_ebpf_filter(interface_list, ebpf_rules):
    if not use_ebpf:
        logging.info("ebpf is disable")
        return
    
    # 调用start.py时 suricata应该是停止状态了
    # TODO: bpftool prog show |grep sr_filter|awk -F: '{print $1}'      bpftool prog detach $id
    for interface in interface_list:
        lmp_map_path = "/sys/fs/bpf/suricata-%s-ipv4_lpm_map" % interface
        # 检查文件存在 防止suricata创建map文件较慢
        for i in range(120):
            if os.path.exists(lmp_map_path):
                logging.info("map file %s is exist", lmp_map_path)
                break
            else:
                time.sleep(1)
        else:
            logging.warning("map file %s is not create", lmp_map_path)

        # 设置过滤条件
        for rule in ebpf_rules:
            logging.info("filter rule: %s", rule)
            if ':' in rule:
                netaddr, port = rule.split(':')
                netaddr = ipv4_to_bytes(netaddr)
                prefix = uint_to_4bytes(32)
                port = uint_to_2bytes(int(port))
            else:
                netaddr, prefix = rule.split('/')
                netaddr = ipv4_to_bytes(netaddr)
                prefix = uint_to_4bytes(int(prefix or 32))
                port = uint_to_2bytes(0)

            cmd = "{} map update pinned {} key {} {} value {}".format(bpftool, lmp_map_path, prefix, netaddr, port)
            logging.info("set ebpf filter: %s", cmd)
            run_command(cmd)

# 获取tap网卡列表
def get_tap_interfaces(config):
    lis = []
    if not config:
        return lis

    logging.info("tap count is %d", tap_count)
    agent = config.get("agent")
    https = config.get("https")
    if agent.get("enable"):
        interface = agent.get("interface", "agent-tap")
        for i in range(tap_count):
            lis.append(interface + str(i))

    if https.get("enable"):
        interface = https.get("interface", "tls-tap")
        for i in range(tap_count):
            lis.append(interface + str(i))

    return lis

# monitor
def read_last_lines(file_path, num_lines=100):
    """读取文件的最后 num_lines 行"""
    with open(file_path, 'r', encoding='utf-8') as file:
        # 使用 deque 来存储最后 num_lines 行
        last_lines = deque(maxlen=num_lines)

        for line in file:
            last_lines.append(line)

    return list(last_lines)  # 返回最后 num_lines 行的列表

def is_process_running(pid):
    try:
        # 使用 os.kill 检查进程是否存在
        os.kill(pid, 0)
    except OSError:
        return False
    return True

def monitor_process_stat():
    count = 0
    last_tcp_syn_value = None
    last_flow_total_value = None

    while True:
        time.sleep(60)
        try:
            with open("/opt/suricata/bin/suricata.pid", 'r') as f:
                pid = int(f.read().strip())
            if not is_process_running(pid):
                logging.warning("suricata process is exit")
                break

            # 读取最后 100 行
            lines = read_last_lines('/opt/suricata/log/stats.log', num_lines=100)
            tcp_syn_value = None
            flow_total_value = None

            # 解析状态参数
            for line in lines:
                if 'tcp.syn' in line and not 'tcp.synack' in line:
                    tcp_syn_value = int(line.split('|')[-1].strip())
                elif 'flow.total' in line:
                    flow_total_value = int(line.split('|')[-1].strip())

            # 检查是否成功读取到值
            if tcp_syn_value is not None and flow_total_value is not None:
                # 判断是否有变化
                if last_tcp_syn_value is not None and last_flow_total_value is not None:
                    if tcp_syn_value == last_tcp_syn_value:
                        continue
                    elif tcp_syn_value != last_tcp_syn_value and flow_total_value == last_flow_total_value:
                        count += 1
                        logging.info(f"case tcp.syn change, flow.total not change, count: {count}")
                    else:
                        logging.info("reset count = 0")
                        count = 0 

                last_tcp_syn_value = tcp_syn_value
                last_flow_total_value = flow_total_value
                if count >= 10:
                    logging.warning("something wrong? restart")
                    subprocess.run(["systemctl", "restart", "suricata"], check=True)
                    count = 0

        except Exception as e:
            logging.warning(f"monitor exception: {e}")


# 启动suricata
def start_suricata(config_data, ebpf_rules):
    # 构建接口命令 
    interface_cmd = ''
    interfaces = []
    if not need_capture:
        # 没有规则就不监听交换机网卡 目的是刚安装mirror时不要推送数据
        logging.info("not need capture nic")
    else:
        interface_arr = config_data.get('nic', [])   
        for interface in interface_arr:
            # 执行脚本检查真实网卡状态并启用网卡（防止设备重启之类的出现网卡未启动等异常）
            cmd = '{}/scripts/check_nic.sh {}'.format(suricata_dir, interface)
            subprocess.call(cmd, shell=True)
            interface_cmd += ' -i {}'.format(interface)
            interfaces.append(interface)
            # 设置ebpf过滤条件
            if use_ebpf:
                lmp_map_path = "/sys/fs/bpf/suricata-%s-ipv4_lpm_map" % interface
                if os.path.exists(lmp_map_path):
                    logging.warning("lmp map file: %s is exist", lmp_map_path)
                    os.remove(lmp_map_path)
                #set_ebpf_filter(interface, ebpf_rules) 不要在这里创建map 否则suricata无法pin成功

    # 检查虚拟接口
    tap_interfaces = get_tap_interfaces(config_data)
    for tap in tap_interfaces:
        for i in range(10):
            try:
                # 检查虚拟接口是否存在
                subprocess.check_output('ip link show {}'.format(tap), shell=True, stderr=subprocess.STDOUT)
                interface_cmd += ' -i {}'.format(tap)
                break
            except subprocess.CalledProcessError:
                logging.warning("%s is not exists", tap)
            time.sleep(1)

    # 检查 Suricata 进程数量
    process_count = int(subprocess.check_output("ps -ef | grep {}/suricata | grep -v grep | wc -l".format(bin_dir), shell=True))
    if process_count == 0:
        # 如果没有进程运行，启动 Suricata
        # 启动前检查logrotate配置
        logrotate_path = '/etc/logrotate.d/suricata'
        if not os.path.exists(logrotate_path):
            logging.warning("The log rotation configuration file %s is not exists", logrotate_path)

        # 启动 Suricata前删除过期的pidfile
        pidfile_path = os.path.join(bin_dir, 'suricata.pid')
        if os.path.exists(pidfile_path):
            os.remove(pidfile_path)

        cmd = '{} -c {}/suricata.yaml {} -k none --pidfile {}'.format(os.path.join(bin_dir, 'suricata'), config_dir, interface_cmd, pidfile_path)
        logging.info("cmd: %s", cmd)
        threading.Thread(target=set_ebpf_filter, args=(interfaces, ebpf_rules)).start()
        threading.Thread(target=monitor_process_stat).start()
        subprocess.call(cmd, shell=True)

# 有效性校验
def is_valid_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        return False
    return True

def is_valid_port(port):
    try:
        port = int(port)
        return 0 < port < 65536
    except ValueError:
        return False

#CIDR表示法
def is_valid_netmask(netmask):
    try:
        network = ipaddress.IPv4Network(netmask)  # '192.168.0.0/16'
        logging.info(f"The network '{network}' is valid.")
        return True
    except ValueError as e:
        logging.warning(f"netmask error: {e}")
        return False

def get_all_ips_from_domain(domain):
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
        logging.info('parse domain: %s -> %s', domain, str(ipaddrlist))
        return ipaddrlist
    except Exception as e:
        logging.warning("parse domain error: %s", str(e))
        return None

# ip段转换为不完全精准的cidr，只是尽可能过滤，多出的日志交给st-controller再过滤掉
#如果全部转换为多个精准的cidr，数量太多了
#a.b.c.d-a.b.c.x -> a.b.c.0/24
#a.b.c.d-a.b.x.? -> a.b.0.0/16
#a.b.c.d-a.x.?.? -> a.0.0.0/8
#a.b.c.d-x.?.?.? -> 0.0.0.0/0
def convert_ipseg_imp_cidr(ip1, ip2):
    ip1_parts = ip1.split('.')
    ip2_parts = ip2.split('.')

    common_items = 0
    ip_parts = []
 
    for i in range(4): 
        if ip1_parts[i] == ip2_parts[i]:
            common_items += 1
            ip_parts.append(ip1_parts[i])
        else:
            break
    
    for j in range(4-common_items):
        ip_parts.append("0")

    mask = common_items * 8
    ip_common = ".".join(ip_parts)
    return "{}/{}".format(ip_common, mask)

# 转换bpf
def convert_bpf(rule_mode, rules_str):
    global contain_all
    rules = set() #去重
    ebpf_rules = []
    contain_all = False  # 是否包含"0.0.0.0/0"这种全网段

    # 暂时只支持in
    if rule_mode not in ["in"]:
        logging.warning(f"rule is not valid: {rule_mode}")
        return rules, ebpf_rules

    for item in set(rules_str.split(",")):
        logging.info("parse rule: %s", item)
        item = item.replace("source:", "", 1).strip()
        if not item:
            continue
        
        if ":" in item:
            # ip:port
            parts = item.split(":")
            if len(parts) == 2 and is_valid_ipv4(parts[0]) and is_valid_port(parts[1]):
                rules.add(" (host {} and port {}) ".format(parts[0], parts[1]))
                ebpf_rules.append(item)
            else:
                logging.warning("invalid ip:port: %s", item)
            continue
        elif '/' in item:
            # ip/mask
            if item == "0.0.0.0/0":
                contain_all = True
                break

            if is_valid_netmask(item):
                rules.add(" (net {}) ".format(item))
                ebpf_rules.append(item)
            else:
                logging.warning("invalid netmask: %s", item)
            continue
        elif '-' in item:
            # ip1-ip2 or domain
            parts = item.split("-")
            if len(parts) == 2 and is_valid_ipv4(parts[0]) and is_valid_ipv4(parts[1]):
                logging.info("found ip1-ip2 format: %s", item)
                if parts[0] == parts[1]:
                    rules.add(" (host {}) ".format(parts[0]))
                    ebpf_rules.append("{}/32".format(parts[0]))
                    continue

                # 转换为不完全精准的CIDR 
                cidr = convert_ipseg_imp_cidr(parts[0], parts[1])
                if cidr == "0.0.0.0/0":
                    contain_all = True
                    break

                rules.add(" (net {}) ".format(cidr))
                ebpf_rules.append(cidr)
                continue
            # 这里无需continue 因为可能是域名

        # 需求:0.0.0.0等同于0.0.0.0/0
        if item == "0.0.0.0":
            contain_all = True
            break

        # 剩余的当作ip or domain处理
        if is_valid_ipv4(item):
            rules.add(" (host {}) ".format(item))
            ebpf_rules.append("{}/32".format(item))
        else:
            ips = get_all_ips_from_domain(item)
            if not ips:
                logging.warning("not valid domain: %s", item)
                continue
            
            ips = ips[0:10]  # 最多只保留10个ip
            for ip in ips:
                rules.add(" (host {}) ".format(ip))
                ebpf_rules.append("{}/32".format(ip))

    if contain_all:
        logging.info("contain all, set bpf str empty")
        rules.clear()
        ebpf_rules.clear()

    return rules, ebpf_rules

# 加载suricata.yaml配置
def gen_yaml_instance():
    yaml = YAML(typ='rt')
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 500
    yaml.default_flow_style = True
    return yaml

# 更新suricata.yaml bpf-filter字段
def update_bpf(suricata_config, config):
    global need_capture, use_ebpf
    ebpf_rules = []

    try:
        bpf_str = ''
        mirror_config = config.get('mirror_filter_v2', {})
        collect_ip = mirror_config.get('collect_ip', '').strip()
        vxlan_enable = config.get("proto", {}).get("vxlan", False)

        if collect_ip == "0.0.0.0/0" or collect_ip == "0.0.0.0":
            # 全部采集，这种情况一般是 过滤范围存在域名或通配符域名，则由7层进行过滤
            bpf_str = ''
        elif collect_ip == "":
            # 范围为空，即全部不采集，此时无需监听交换机业务网口
            logging.info("rule is empty, not need capture interface")
            need_capture = False
        elif vxlan_enable:
            # 不支持vxlan bpf过滤
            bpf_str = ''
        else:
            # 执行范围采集
            rule_mode = "in"
            rules, ebpf_rules = convert_bpf(rule_mode, collect_ip)
            if not contain_all:
                # ebpf方案
                logging.info("filter ebpf is enable, rules size: %s", len(rules))
                use_ebpf = True

        logging.info("suricata bpf-filter: %s", bpf_str)    
        af_packet_conf = suricata_config.get('af-packet', [])
        for item in af_packet_conf:
            logging.info("interface:%s, bpf-filter:%s", item.get('interface'), item.get("bpf-filter", ""))
            if item.get('interface') == 'default':
                # "default"表示除了agent-tap0外的其他网卡
                if not use_ebpf:
                    logging.info("update af-packet default bpf-filter: %s", bpf_str)
                    item["bpf-filter"] = bpf_str
                    if "ebpf-filter-file" in item:
                        del item["ebpf-filter-file"]
                else:
                    logging.info("update af-packet default set ebpf-filter-file: %s", sr_filter_ebpf)
                    item["ebpf-filter-file"] = sr_filter_ebpf
    except Exception as e:
        logging.warning("update_bpf exception: %s", str(e))

    return ebpf_rules

# 获取设备内存
def get_total_memory():
    with open('/proc/meminfo', 'r') as f:
        for line in f:
            if line.startswith('MemTotal'):
                total_memory_kb = int(line.split()[1])  # 以KB为单位
                return total_memory_kb / (1024 ** 2)  # 转换为GB

# 获取CPU数量
def get_cpu_count():
    return os.cpu_count()


def update_suricata_yaml(suricata_config, config):
    # 要求只有一个业务网卡
    if len(config.get("nic", [])) > 1:
        logging.warning("mirror interface count is more than 1: %s", len(config.get("nic", [])))
        return

    total_memory = get_total_memory()
    cpu_count = get_cpu_count()
    logging.info("sys info: cpu count = %s, total_memory = %s", cpu_count, total_memory)

    suri_threads = int(math.ceil(total_memory) / 2)  # 2GB内存/线程
    if suri_threads > 8:
        suri_threads = 8

    memcap = int(math.ceil(total_memory/4))
    if memcap > 8:
        memcap = 8

    logging.info("set suri_thread: %d, memcap: %d", suri_threads, memcap)
    try:
        # threads
        af_packet_conf = suricata_config.get('af-packet', [])
        for item in af_packet_conf:
            logging.info("interface:%s, bpf-filter:%s", item.get('interface'), item.get("bpf-filter", ""))
            if item.get('interface') == 'default':
                item["threads"] = suri_threads
        # memcap
        stream_conf = suricata_config.get('stream', {})
        stream_conf['memcap'] = str(memcap) + "gb"
        reassembly_conf = stream_conf.get('reassembly', {})
        reassembly_conf['memcap'] = str(memcap) + "gb"
    except Exception as e:
        logging.warning("update suricata yaml exception: %s", str(e))


# 性能模式配置更新
def update_suricata_performance_yaml(suricata_config, config):
    # 要求只有一个业务网卡
    if len(config.get("nic", [])) > 1:
        logging.warning("mirror interface count is more than 1: %s", len(config.get("nic", [])))
        return

    total_memory = get_total_memory()
    cpu_count = get_cpu_count()
    logging.info("sys info: cpu count = %s, total_memory = %s", cpu_count, total_memory)
    # 至少需要32核cpu，32GB内存(实际上得到的值会少于32GB)
    if cpu_count < 32 or math.ceil(total_memory) < 32:
        logging.info("is not high-performance device")
        return 
    
    logging.info("is high-performance device")
    first_cpu_index = cpu_count - 16
    last_cpu_index = cpu_count - 1
    flow_manage_cpu_index = first_cpu_index - 1

    try:
        # 网卡线程配置
        af_packet_conf = suricata_config.get('af-packet', [])
        for item in af_packet_conf:
            logging.info("interface:%s, bpf-filter:%s", item.get('interface'), item.get("bpf-filter", ""))
            if item.get('interface') == 'default':
                item["threads"] = 16  # 16个工作线程线程
                item["ring-size"] = 30000
                item["block-size"] = 1024 * 1024
        # CPU亲和力配置
        cpu_affinity_conf = suricata_config.get('threading', {})
        cpu_affinity_conf['set-cpu-affinity'] = True
        cpu_affinity = cpu_affinity_conf.get('cpu-affinity', [])
        cpu_affinity[0].get('management-cpu-set', {})['cpu'] = [flow_manage_cpu_index]
        cpu_affinity[1].get('receive-cpu-set', {})['cpu'] = [flow_manage_cpu_index]
        work_cpu_set = cpu_affinity[2].get('worker-cpu-set', {})
        work_cpu_set['cpu'] = [f"{first_cpu_index}-{last_cpu_index}"] # 工作线程cpu
        # memcap
        stream_conf = suricata_config.get('stream', {})
        stream_conf['memcap'] = str(math.ceil(total_memory/2)) + "gb"
        reassembly_conf = stream_conf.get('reassembly', {})
        reassembly_conf['memcap'] = str(math.ceil(total_memory/2)) + "gb" #"1200mb"
    except Exception as e:
        logging.warning("update_suricata_yaml exception: %s", str(e))


def update_interface(config, af_packet_list, templa, cluster_id):
    global interface_config
    if config and config.get("enable"):
        interface = config.get("interface", "agent-tap")
        #count = config.get("interface_count", 1)
        logging.info("update_interface:%s, count:%d", interface, tap_count)
        for i in range(tap_count):
            templa["interface"] = interface + str(i)
            templa["threads"] = 1
            templa["cluster-id"] = cluster_id
            cluster_id = cluster_id + 1
            af_packet_list.append(copy.copy(templa))


def update_interface_config(suricata_config, config):
    defaul = {}
    templa = {}

    try:
        af_packet_conf = suricata_config.get('af-packet', [])
        for item in af_packet_conf:
            if item.get('interface') == 'agent-tap0':
                templa = item
            elif item.get('interface') == 'default':
                defaul = item

        af_packet_conf.clear()
        af_packet_conf.append(defaul) #只留下default,其他网口根据配置生成

        agent_config = config.get("agent")
        update_interface(agent_config, af_packet_conf, templa, 100)
        https_config = config.get("https")
        update_interface(https_config, af_packet_conf, templa, 200)
    except Exception as e:
        logging.warning("update_interface_config exception: %s", str(e))

# 加载yaml
def load_yaml_config(yaml_instance, yaml_file):
    suricata_config = {}
    if not os.path.isfile(yaml_file):
        logging.warning(f"YAML file {yaml_file} is not exist")
        return suricata_config

    try:
        with open(yaml_file, 'r', encoding='utf-8') as file:
            suricata_config = yaml_instance.load(file)
    except Exception as e:
        logging.warning(f"open yaml file failed: {e}")

    return suricata_config


def dump_yaml_config(yaml_instance, yaml_config):
    try:
        with open(suricata_yaml_file, 'w', encoding='utf-8') as file:
            yaml_instance.dump(yaml_config, file)
    except Exception as e:
        logging.warning(f"open yaml file failed: {e}")

def ebpf_lb_vxlan_support(yaml_config, json_conf):
    try:
        # 获取 'vxlan' 的值
        vxlan = json_conf.get("proto", {}).get("vxlan", None)

        # 修改 YAML 配置文件中的 'af-packet' 部分
        for item in yaml_config.get('af-packet', []):
            if item.get('interface') == 'default':
                if vxlan:
                    # 如果 vxlan 为 True，修改 'cluster-type' 和追加 'ebpf-lb-file'
                    item['cluster-type'] = 'cluster_ebpf'
                    item['ebpf-lb-file'] = vxlan_lb_ebpf
                    logging.info("启用 VxLAN 支持, 加载 %s 程序", vxlan_lb_ebpf)
                else:
                    # 如果 vxlan 为 False，修改 'cluster-type' 和删除 'ebpf-lb-file'
                    # FIXME: 解决单边vlan的问题，后续日志仅使用一条时再去除相关逻辑
                    item['cluster-type'] = 'cluster_ebpf'
                    item['ebpf-lb-file'] = sr_lb_ebpf
                    logging.info("禁用 VxLAN 支持")

    except Exception as e:
        logging.warning("ebpf_lb_vxlan_support exception: %s", str(e))


def update_proto_vlan(yaml_config, config):
    proto_config = config.get("proto", {})
    # vlan (flow id)
    vlan_config = yaml_config.get('vlan', {})
    vlan_config["use-for-tracking"] = proto_config.get("vlan", False)


def update_proto_config(yaml_config, config):
    ebpf_lb_vxlan_support(yaml_config, config)
    update_proto_vlan(yaml_config, config)


def main():
    # 初始化
    init_log()
    # 读取配置
    config_data = read_config(config_json_file)
    custom_data = read_config(custom_json_file)
    config_data.update(custom_data)
    # suricata.yaml配置
    yaml_instance = gen_yaml_instance()
    yaml_config = load_yaml_config(yaml_instance, suricata_yaml_template)
    # 更新bpf过滤条件
    ebpf_rules = update_bpf(yaml_config, config_data)
    # 更新网卡配置
    update_interface_config(yaml_config, config_data)
    # 更新配置
    update_suricata_yaml(yaml_config, config_data)
    # 性能模式配置文件更新
    update_suricata_performance_yaml(yaml_config, config_data)
    # 更新协议配置
    update_proto_config(yaml_config, config_data)
    # 更新suricata.yaml配置文件
    dump_yaml_config(yaml_instance, yaml_config)
    # 启动suricata
    start_suricata(config_data, ebpf_rules)


# unit test
class TestConvertBpfFunction(unittest.TestCase):
    def setUp(self):
        global contain_all
        contain_all = False

    # 范围为空
    def test_empty(self):
        rules, ebpf = convert_bpf("in", "")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 非法参数
    def test_err1(self):
        rules, ebpf = convert_bpf("in", "abc")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 正常单个ip
    def test_ip1(self):
        rules, ebpf = convert_bpf("in", "1.2.3.4")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 1.2.3.4) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("1.2.3.4/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常ip
    def test_ip2(self):
        rules, ebpf = convert_bpf("in", "1.2.3.4\n")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 1.2.3.4) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("1.2.3.4/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 错误ip
    def test_ip3(self):
        rules, ebpf = convert_bpf("in", "192.168.0.256")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 正常ip+端口
    def test_ip_port1(self):
        rules, ebpf = convert_bpf("in", "2.3.4.5:8080")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 2.3.4.5 and port 8080) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("2.3.4.5:8080" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常ip 异常端口
    def test_ip_port2(self):
        rules, ebpf = convert_bpf("in", "2.3.4.5:65536")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 正常ip 异常端口
    def test_ip_port3(self):
        rules, ebpf = convert_bpf("in", "2.3.4.5:a")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 全0网段
    def test_cird1(self):
        rules, ebpf = convert_bpf("in", "0.0.0.0/0")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, True)

    # 正常网段
    def test_cird2(self):
        rules, ebpf = convert_bpf("in", "0.0.0.0/24")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 0.0.0.0/24) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("0.0.0.0/24" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常网段
    def test_cird3(self):
        rules, ebpf = convert_bpf("in", "192.168.0.0/16")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 192.168.0.0/16) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("192.168.0.0/16" in ebpf, True)

    # 非法格式的网段
    def test_cird4(self):
        rules, ebpf = convert_bpf("in", "1.1.1.1/24")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # 正常网段
    def test_cird5(self):
        rules, ebpf = convert_bpf("in", "10.0.0.0/8")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/8) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/8" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常域名
    def test_domain1(self):
        rules, ebpf = convert_bpf("in", "zt.ouryun.cn")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 192.168.1.63) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("192.168.1.63/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 域名+端口不支持
    def test_domain2(self):
        rules, ebpf = convert_bpf("in", "zt.ouryun.cn:443")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)
    
    # 域名带-
    def test_domain3(self):
        rules, ebpf = convert_bpf("in", "example-brand.com")
        ips = get_all_ips_from_domain("example-brand.com")
        if not ips:
            self.assertEqual(len(rules), 0)
            self.assertEqual(len(ebpf), 0)
        else:
            ips = ips[0:10]
            for ip in ips:
                self.assertEqual(" (host {}) ".format(ip) in rules, True)
                self.assertEqual("{}/32".format(ip) in ebpf, True)
        self.assertEqual(contain_all, False)

    # 无效域名
    def test_domain4(self):
        rules, ebpf = convert_bpf("in", "notexist-website.webs,192.168.0.1")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 192.168.0.1) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("192.168.0.1/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常域名组合
    def test_domain5(self):
        rules, ebpf = convert_bpf("in", "example-brand.com,192.168.0.1")
        ips = get_all_ips_from_domain("example-brand.com")
        self.assertEqual(" (host 192.168.0.1) " in rules, True)
        self.assertEqual("192.168.0.1/32" in ebpf, True)
        if not ips:
            self.assertEqual(len(rules), 1)
            self.assertEqual(len(ebpf), 1)
        else:
            ips = ips[0:10]
            for ip in ips:
                self.assertEqual(" (host {}) ".format(ip) in rules, True)
                self.assertEqual("{}/32".format(ip) in ebpf, True)
        self.assertEqual(contain_all, False)
    
    # 正常网段
    def test_iprange1(self):
        rules, ebpf = convert_bpf("in", "192.168.0.1-192.168.0.1")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 192.168.0.1) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("192.168.0.1/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 全网段
    def test_iprange2(self):
        rules, ebpf = convert_bpf("in", "0.0.0.0-255.255.255.255")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, True)
        
    # 正常网段
    def test_iprange3(self):
        rules, ebpf = convert_bpf("in", "10.0.0.1-10.0.0.2")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/24) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/24" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常网段
    def test_iprange4(self):
        rules, ebpf = convert_bpf("in", "10.0.0.1-10.0.1.2")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/16) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/16" in ebpf, True)
        self.assertEqual(contain_all, False)
        
    # 正常网段
    def test_iprange5(self):
        rules, ebpf = convert_bpf("in", "10.0.0.1-10.1.1.2")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/8) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/8" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 正常网段
    def test_iprange6(self):
        rules, ebpf = convert_bpf("in", "10.0.0.1-11.0.1.2")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, True)

    # 混合
    def test_mix1(self):
        rules, ebpf = convert_bpf("in", "zy.ouryun.cn,zt.ouryun.cn,192.169.0.1,255.255.255.256,200.0.0.1-200.1.0.1,200.0.0.1-200.0.0.256,10.10.0.0/16,10.0.0.0/33,8.8.8.8:8888,8.8.8.8:65536")
        self.assertEqual(len(rules), 5)
        self.assertEqual(" (host 192.168.1.63) " in rules, True)
        self.assertEqual(" (host 192.169.0.1) " in rules, True)
        self.assertEqual(" (net 200.0.0.0/8) " in rules, True)
        self.assertEqual(" (net 10.10.0.0/16) " in rules, True)
        self.assertEqual(" (host 8.8.8.8 and port 8888) " in rules, True)

        self.assertEqual(len(ebpf), 5)
        self.assertEqual("192.168.1.63/32" in ebpf, True)
        self.assertEqual("192.169.0.1/32" in ebpf, True)
        self.assertEqual("200.0.0.0/8" in ebpf, True)
        self.assertEqual("10.10.0.0/16" in ebpf, True)
        self.assertEqual("8.8.8.8:8888" in ebpf, True)
        self.assertEqual(contain_all, False)

    # 混合
    def test_mix2(self):
        rules, ebpf = convert_bpf("in", "192.168.0.1,0.0.0.0/0,200.0.0.1")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, True)

    # 混合
    def test_mix3(self):
        rules, ebpf = convert_bpf("in", "192.168.0.1,0.0.0.0-255.255.255.255,200.0.0.1")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, True)

    # source
    def test_source_error1(self):
        rules, ebpf = convert_bpf("in", "source:abc")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # source
    def test_source_error2(self):
        rules, ebpf = convert_bpf("in", "source:192.168.0.256")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # source
    def test_source_error3(self):
        rules, ebpf = convert_bpf("in", "source1:192.168.0.1")
        self.assertEqual(len(rules), 0)
        self.assertEqual(len(ebpf), 0)
        self.assertEqual(contain_all, False)

    # source
    def test_source_ip1(self):
        rules, ebpf = convert_bpf("in", "source:1.2.3.4")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 1.2.3.4) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("1.2.3.4/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # source
    def test_source_ip_port1(self):
        rules, ebpf = convert_bpf("in", "source:2.3.4.5:8080")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 2.3.4.5 and port 8080) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("2.3.4.5:8080" in ebpf, True)
        self.assertEqual(contain_all, False)

    # source
    def test_source_cidr1(self):
        rules, ebpf = convert_bpf("in", "source:10.0.0.0/8")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/8) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/8" in ebpf, True)
        self.assertEqual(contain_all, False)

    # source 
    def test_source_domain1(self):
        rules, ebpf = convert_bpf("in", "source:zt.ouryun.cn")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (host 192.168.1.63) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("192.168.1.63/32" in ebpf, True)
        self.assertEqual(contain_all, False)

    # source 
    def test_source_iprange1(self):
        rules, ebpf = convert_bpf("in", "source:10.0.0.1-10.0.1.2")
        self.assertEqual(len(rules), 1)
        self.assertEqual(" (net 10.0.0.0/16) " in rules, True)
        self.assertEqual(len(ebpf), 1)
        self.assertEqual("10.0.0.0/16" in ebpf, True)
        self.assertEqual(contain_all, False)

    # source 
    def test_source_mix1(self):
        rules, ebpf = convert_bpf("in", "source:zy.ouryun.cn,source:zt.ouryun.cn,source:192.169.0.1,source:255.255.255.256,source:200.0.0.1-200.1.0.1,source:200.0.0.1-200.0.0.256,source:10.10.0.0/16,source:10.0.0.0/33,source:8.8.8.8:8888,source:8.8.8.8:65536")
        self.assertEqual(len(rules), 5)
        self.assertEqual(" (host 192.168.1.63) " in rules, True)
        self.assertEqual(" (host 192.169.0.1) " in rules, True)
        self.assertEqual(" (net 200.0.0.0/8) " in rules, True)
        self.assertEqual(" (net 10.10.0.0/16) " in rules, True)
        self.assertEqual(" (host 8.8.8.8 and port 8888) " in rules, True)

        self.assertEqual(len(ebpf), 5)
        self.assertEqual("192.168.1.63/32" in ebpf, True)
        self.assertEqual("192.169.0.1/32" in ebpf, True)
        self.assertEqual("200.0.0.0/8" in ebpf, True)
        self.assertEqual("10.10.0.0/16" in ebpf, True)
        self.assertEqual("8.8.8.8:8888" in ebpf, True)
        self.assertEqual(contain_all, False)


def unit_test():
    suite = unittest.TestSuite()
    suite.addTest(TestConvertBpfFunction("test_empty"))
    suite.addTest(TestConvertBpfFunction("test_err1"))
    suite.addTest(TestConvertBpfFunction("test_ip1"))
    suite.addTest(TestConvertBpfFunction("test_ip2"))
    suite.addTest(TestConvertBpfFunction("test_ip3"))
    suite.addTest(TestConvertBpfFunction("test_ip_port1"))
    suite.addTest(TestConvertBpfFunction("test_ip_port2"))
    suite.addTest(TestConvertBpfFunction("test_ip_port3"))
    suite.addTest(TestConvertBpfFunction("test_cird1"))
    suite.addTest(TestConvertBpfFunction("test_cird2"))
    suite.addTest(TestConvertBpfFunction("test_cird3"))
    suite.addTest(TestConvertBpfFunction("test_cird4"))
    suite.addTest(TestConvertBpfFunction("test_cird5"))
    suite.addTest(TestConvertBpfFunction("test_domain1"))
    suite.addTest(TestConvertBpfFunction("test_domain2"))
    suite.addTest(TestConvertBpfFunction("test_domain3"))
    suite.addTest(TestConvertBpfFunction("test_domain4"))
    suite.addTest(TestConvertBpfFunction("test_domain5"))
    suite.addTest(TestConvertBpfFunction("test_iprange1"))
    suite.addTest(TestConvertBpfFunction("test_iprange2"))
    suite.addTest(TestConvertBpfFunction("test_iprange3"))
    suite.addTest(TestConvertBpfFunction("test_iprange4"))
    suite.addTest(TestConvertBpfFunction("test_iprange5"))
    suite.addTest(TestConvertBpfFunction("test_iprange6"))
    suite.addTest(TestConvertBpfFunction("test_mix1"))
    suite.addTest(TestConvertBpfFunction("test_mix2"))
    suite.addTest(TestConvertBpfFunction("test_mix3"))

    suite.addTest(TestConvertBpfFunction("test_source_error1"))
    suite.addTest(TestConvertBpfFunction("test_source_error2"))
    suite.addTest(TestConvertBpfFunction("test_source_error3"))
    suite.addTest(TestConvertBpfFunction("test_source_ip1"))
    suite.addTest(TestConvertBpfFunction("test_source_ip_port1"))
    suite.addTest(TestConvertBpfFunction("test_source_cidr1"))
    suite.addTest(TestConvertBpfFunction("test_source_domain1"))
    suite.addTest(TestConvertBpfFunction("test_source_iprange1"))
    suite.addTest(TestConvertBpfFunction("test_source_mix1"))

    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        param = sys.argv[1]
        if param == "unittest":
            unit_test()
            sys.exit(0)
        else:
            tap_count = int(param)

    main()

