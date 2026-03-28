# -*- coding: utf-8 -*-

import subprocess
import time
import requests
import logging
import os
import platform
import tempfile
from urllib.parse import quote
from .config_generator import save_clash_config

logger = logging.getLogger("Sub")


class MihomoClient:
    """
    Mihomo (Clash Meta) client manager.
    Handles lifecycle, configuration, and API interactions.
    """
    
    def __init__(self, mihomo_bin="mihomo", api_port=9090, socks_port=7891):
        """
        Initialize Mihomo client.
        
        Args:
            mihomo_bin: Path to mihomo binary (default: "mihomo")
            api_port: External controller API port (default: 9090)
            socks_port: SOCKS5 proxy port (default: 7891)
        """
        # Check for mihomo binary based on OS
        if not os.path.exists(mihomo_bin):
            if platform.system() == "Windows":
                mihomo_bin = "./clients/mihomo/mihomo.exe"
            else:
                mihomo_bin = "./clients/mihomo/mihomo"
        
        self.mihomo_bin = mihomo_bin
        self.api_port = api_port
        self.socks_port = socks_port
        self.api_url = f"http://127.0.0.1:{api_port}"
        self.process = None
        self.config_path = None
        
    def start(self, config):
        """
        Start Mihomo with given configuration.
        
        Args:
            config: Clash configuration dict
            
        Returns:
            bool: True if started successfully
        """
        if self.process and self.process.poll() is None:
            logger.warning("Mihomo already running")
            return True
            
        # Save config to temp file
        self.config_path = os.path.join(tempfile.gettempdir(), "clash_config.yaml")
        save_clash_config(config, self.config_path)
        
        # Start Mihomo process
        try:
            self.process = subprocess.Popen(
                [self.mihomo_bin, '-f', self.config_path, '-d', tempfile.gettempdir()],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for startup
            time.sleep(2)
            
            # Check if started successfully
            if self.is_healthy():
                logger.info("Mihomo started successfully")
                return True
            else:
                logger.error("Mihomo failed to start")
                self.stop()
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Mihomo: {e}")
            return False
    
    def stop(self):
        """Stop Mihomo process."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("Mihomo stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.warning("Mihomo killed (timeout)")
            except Exception as e:
                logger.error(f"Error stopping Mihomo: {e}")
            finally:
                self.process = None
                
        # Clean up config file
        if self.config_path and os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
            except:
                pass
    
    def is_healthy(self):
        """
        Check if Mihomo API is responding.
        
        Returns:
            bool: True if API responds
        """
        try:
            response = requests.get(f"{self.api_url}/version", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def update_config(self, config):
        """
        Update Mihomo configuration dynamically.
        
        Args:
            config: New Clash configuration dict
            
        Returns:
            bool: True if updated successfully
        """
        if not self.config_path:
            logger.error("No config path set")
            return False
            
        try:
            # Save new config
            save_clash_config(config, self.config_path)
            
            # Reload via API
            response = requests.put(
                f"{self.api_url}/configs",
                params={"force": "true"},
                json={"path": self.config_path},
                timeout=5
            )
            
            if response.status_code == 204:
                logger.debug("Config reloaded successfully")
                return True
            else:
                logger.error(f"Failed to reload config: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return False

    def select_proxy(self, group_name, proxy_name):
        """
        Select a proxy inside a selector group.

        Args:
            group_name: Selector group name
            proxy_name: Proxy name to activate

        Returns:
            bool: True if updated successfully
        """
        try:
            group_name = quote(group_name, safe="")
            response = requests.put(
                f"{self.api_url}/proxies/{group_name}",
                json={"name": proxy_name},
                timeout=5
            )

            if response.status_code == 204:
                logger.debug(f"Selected proxy {proxy_name} in group {group_name}")
                return True

            logger.error(f"Failed to select proxy {proxy_name}: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"Error selecting proxy {proxy_name}: {e}")
            return False

    def test_group_delay(self, group_name, test_url="https://www.gstatic.com/generate_204", timeout=5000):
        """
        Test all proxies inside a selector group via Mihomo API.

        Args:
            group_name: Selector group name
            test_url: URL to test against
            timeout: Timeout in milliseconds

        Returns:
            dict: Mapping of proxy name to delay in milliseconds
        """
        try:
            group_name = quote(group_name, safe="")
            response = requests.get(
                f"{self.api_url}/group/{group_name}/delay",
                params={"url": test_url, "timeout": timeout},
                timeout=(timeout / 1000) + 5
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    if "delay" in data and isinstance(data["delay"], dict):
                        data = data["delay"]
                    logger.debug(f"Group {group_name} delay test returned {len(data)} entries")
                    return data
                logger.warning(f"Unexpected group delay response for {group_name}: {data}")
                return {}

            logger.warning(f"Group delay test failed for {group_name}: {response.status_code}")
            return {}
        except requests.exceptions.Timeout:
            logger.warning(f"Group delay test timeout for {group_name}")
            return {}
        except Exception as e:
            logger.error(f"Error testing group delay for {group_name}: {e}")
            return {}
    
    def test_delay(self, proxy_name, test_url="https://www.gstatic.com/generate_204", timeout=5000):
        """
        Test proxy delay via Mihomo API.
        
        Args:
            proxy_name: Name of proxy to test
            test_url: URL to test against (default: Google generate_204)
            timeout: Timeout in milliseconds (default: 5000)
            
        Returns:
            int: Delay in milliseconds, 0 if failed
        """
        try:
            proxy_name = quote(proxy_name, safe="")
            response = requests.get(
                f"{self.api_url}/proxies/{proxy_name}/delay",
                params={"url": test_url, "timeout": timeout},
                timeout=(timeout / 1000) + 2
            )
            
            if response.status_code == 200:
                data = response.json()
                delay = data.get("delay", 0)
                logger.debug(f"Proxy {proxy_name} delay: {delay}ms")
                return delay
            else:
                logger.warning(f"Delay test failed for {proxy_name}: {response.status_code}")
                return 0
                
        except requests.exceptions.Timeout:
            logger.warning(f"Delay test timeout for {proxy_name}")
            return 0
        except Exception as e:
            logger.error(f"Error testing delay for {proxy_name}: {e}")
            return 0
    
    def __del__(self):
        """Cleanup on deletion."""
        self.stop()
