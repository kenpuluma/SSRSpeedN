# -*- coding: utf-8 -*-

import yaml
import logging

logger = logging.getLogger("Sub")


def node_to_clash_proxy(node):
    """
    Convert SSRSpeedN node to Clash proxy configuration.
    
    Args:
        node: BaseNode instance with node_type and config properties
        
    Returns:
        dict: Clash proxy configuration
    """
    cfg = node.config
    node_type = node.node_type
    
    # Base proxy config
    proxy = {
        "name": cfg.get("remarks", "proxy"),
        "server": cfg["server"],
        "port": int(cfg["server_port"]),
    }
    
    if node_type == "Shadowsocks":
        proxy.update({
            "type": "ss",
            "cipher": cfg["method"],
            "password": cfg["password"],
            "udp": cfg.get("udp", True),
        })
        # Handle plugin (simple-obfs)
        if cfg.get("plugin"):
            proxy["plugin"] = cfg["plugin"]
            if cfg.get("plugin_opts"):
                proxy["plugin-opts"] = cfg["plugin_opts"]
                
    elif node_type == "ShadowsocksR":
        proxy.update({
            "type": "ssr",
            "cipher": cfg["method"],
            "password": cfg["password"],
            "protocol": cfg.get("protocol", "origin"),
            "obfs": cfg.get("obfs", "plain"),
            "protocol-param": cfg.get("protocol_param", ""),
            "obfs-param": cfg.get("obfs_param", ""),
            "udp": cfg.get("udp", True),
        })
        
    elif node_type == "V2Ray":
        # VMess protocol
        proxy.update({
            "type": "vmess",
            "uuid": cfg["id"],
            "alterId": cfg.get("alterId", 0),
            "cipher": cfg.get("cipher", "auto"),
            "udp": cfg.get("udp", True),
        })
        # Network type
        if cfg.get("net"):
            proxy["network"] = cfg["net"]
        # TLS
        if cfg.get("tls"):
            proxy["tls"] = True
            if cfg.get("sni"):
                proxy["servername"] = cfg["sni"]
        # WebSocket
        if cfg.get("net") == "ws":
            if cfg.get("path"):
                proxy["ws-path"] = cfg["path"]
            if cfg.get("host"):
                proxy["ws-headers"] = {"Host": cfg["host"]}
        # HTTP/2
        elif cfg.get("net") == "h2":
            if cfg.get("path"):
                proxy["h2-opts"] = {"path": cfg["path"]}
            if cfg.get("host"):
                proxy["h2-opts"]["host"] = [cfg["host"]]
        # gRPC
        elif cfg.get("net") == "grpc":
            if cfg.get("path"):
                proxy["grpc-opts"] = {"grpc-service-name": cfg["path"]}
                
    elif node_type == "Trojan":
        proxy.update({
            "type": "trojan",
            "password": cfg["password"],
            "udp": cfg.get("udp", True),
        })
        # SNI
        if cfg.get("sni"):
            proxy["sni"] = cfg["sni"]
        # Skip cert verify
        if cfg.get("skip-cert-verify"):
            proxy["skip-cert-verify"] = True
        # WebSocket
        if cfg.get("network") == "ws":
            proxy["network"] = "ws"
            if cfg.get("ws-path"):
                proxy["ws-opts"] = {"path": cfg["ws-path"]}
            if cfg.get("ws-headers"):
                proxy["ws-opts"]["headers"] = cfg["ws-headers"]
    else:
        logger.warning(f"Unknown node type: {node_type}, using as-is")
        
    return proxy


def generate_clash_config(proxy, socks_port=7891, api_port=9090):
    """
    Generate complete Clash configuration with single proxy.
    
    Args:
        proxy: Clash proxy dict from node_to_clash_proxy()
        socks_port: SOCKS5 proxy port (default: 7891)
        api_port: External controller API port (default: 9090)
        
    Returns:
        dict: Complete Clash configuration
    """
    config = {
        "mixed-port": 7890,
        "socks-port": socks_port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": "",
        
        "proxies": [proxy],
        
        "proxy-groups": [
            {
                "name": "GLOBAL",
                "type": "select",
                "proxies": [proxy["name"]]
            }
        ],
        
        "rules": [
            "MATCH,GLOBAL"
        ]
    }
    
    return config


def save_clash_config(config, filepath):
    """
    Save Clash configuration to YAML file.
    
    Args:
        config: Clash configuration dict
        filepath: Output file path
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    logger.debug(f"Clash config saved to {filepath}")
