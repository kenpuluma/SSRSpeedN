# -*- coding: utf-8 -*-

from copy import deepcopy
import yaml
import logging

logger = logging.getLogger("Sub")


def node_to_clash_proxy(node, proxy_name=None):
    """
    Convert SSRSpeedN node to Clash proxy configuration.
    
    Args:
        node: BaseNode instance with node_type and config properties
        proxy_name: Optional name override for Mihomo to avoid collisions
        
    Returns:
        dict: Clash proxy configuration
    """
    cfg = node.config
    node_type = node.node_type

    if cfg.get("raw_proxy"):
        proxy = deepcopy(cfg["raw_proxy"])
        if proxy_name:
            proxy["name"] = proxy_name
        elif cfg.get("remarks"):
            proxy["name"] = cfg["remarks"]
        if "port" in proxy:
            proxy["port"] = int(proxy["port"])
        return proxy
    
    # Base proxy config
    proxy = {
        "name": proxy_name or cfg.get("remarks", "proxy"),
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
        net = cfg.get("network") or cfg.get("net")
        tls_raw = cfg.get("tls")
        tls_enabled = tls_raw in (True, 1, "1", "true", "tls")
        proxy.update({
            "type": "vmess",
            "uuid": cfg["id"],
            "alterId": int(cfg.get("alterId", 0)),
            "cipher": cfg.get("cipher") or cfg.get("security", "auto"),
            "udp": cfg.get("udp", True),
        })
        # TLS / SNI / cert verification
        if tls_enabled:
            proxy["tls"] = True
            servername = cfg.get("sni") or cfg.get("tls-host") or cfg.get("host")
            if servername:
                proxy["servername"] = servername
        if cfg.get("allowInsecure"):
            proxy["skip-cert-verify"] = True
        # Network type
        if net:
            proxy["network"] = net
        # WebSocket
        if net == "ws":
            ws_opts = {}
            if cfg.get("path"):
                ws_opts["path"] = cfg["path"]
            if cfg.get("host"):
                ws_opts["headers"] = {"Host": cfg["host"]}
            if ws_opts:
                proxy["ws-opts"] = ws_opts
        # HTTP/2
        elif net == "h2":
            h2_opts = {}
            if cfg.get("path"):
                h2_opts["path"] = cfg["path"]
            if cfg.get("host"):
                h2_opts["host"] = cfg["host"]
            if h2_opts:
                proxy["h2-opts"] = h2_opts
        # gRPC
        elif net == "grpc":
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
        # Network / transport
        network = cfg.get("network")
        if network:
            proxy["network"] = network
        # WebSocket
        if network == "ws":
            ws_opts = {}
            ws_path = cfg.get("ws-path") or cfg.get("path")
            ws_headers = cfg.get("ws-headers")
            host = cfg.get("host")
            if ws_path:
                ws_opts["path"] = ws_path
            if ws_headers:
                ws_opts["headers"] = ws_headers
            elif host:
                ws_opts["headers"] = {"Host": host}
            if ws_opts:
                proxy["ws-opts"] = ws_opts
        # gRPC
        elif network == "grpc":
            service_name = cfg.get("grpc-service-name") or cfg.get("path")
            if service_name:
                proxy["grpc-opts"] = {"grpc-service-name": service_name}
        # HTTP/2
        elif network == "h2":
            h2_opts = {}
            if cfg.get("path"):
                h2_opts["path"] = cfg["path"]
            if cfg.get("host"):
                h2_opts["host"] = cfg["host"]
            if h2_opts:
                proxy["h2-opts"] = h2_opts
    else:
        logger.warning(f"Unknown node type: {node_type}, using as-is")
        
    return proxy


def generate_clash_config(proxies, socks_port=7891, api_port=9090, group_name="GLOBAL"):
    """
    Generate complete Clash configuration.
    
    Args:
        proxies: Clash proxy dict or list of proxy dicts from node_to_clash_proxy()
        socks_port: SOCKS5 proxy port (default: 7891)
        api_port: External controller API port (default: 9090)
        group_name: Proxy group name (default: "GLOBAL")
        
    Returns:
        dict: Complete Clash configuration
    """
    if isinstance(proxies, dict):
        proxies = [proxies]

    if not proxies:
        raise ValueError("At least one proxy is required to generate Clash config")

    proxy_names = [proxy["name"] for proxy in proxies]

    config = {
        "mixed-port": 7890,
        "socks-port": socks_port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": "",
        
        "proxies": proxies,
        
        "proxy-groups": [
            {
                "name": group_name,
                "type": "select",
                "proxies": proxy_names
            }
        ],
        
        "rules": [
            f"MATCH,{group_name}"
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
