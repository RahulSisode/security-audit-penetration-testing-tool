"""
Module: scanner_orchestrator.py
Description: Asynchronous execution service for network banner checking 
             and containerized OWASP ZAP baseline audits using Docker SDK.
"""

import os
import json
import socket
import logging
import urllib.parse
from typing import Dict, Any, Optional, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ScannerOrchestrator")


def execute_infrastructure_map(target_ip_or_domain: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Safely probes standard ports using non-privileged TCP socket connections,
    retrieves server identification banners if exposed, and returns structured data.
    """
    if ports is None:
        # Standard non-destructive service ports for discovery
        ports = [80, 443, 8080, 8443]

    results: Dict[str, Any] = {
        "target": target_ip_or_domain,
        "resolved_ip": None,
        "ports": []
    }

    try:
        resolved_ip = socket.gethostbyname(target_ip_or_domain)
        results["resolved_ip"] = resolved_ip
    except socket.gaierror as e:
        logger.error(f"DNS resolution failure for {target_ip_or_domain}: {e}")
        return results

    for port in ports:
        port_info = {"port": port, "state": "closed", "banner": None}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)

        try:
            conn = sock.connect_ex((resolved_ip, port))
            if conn == 0:
                port_info["state"] = "open"
                # Send safe HTTP HEAD request to collect server banner if web service
                if port in (80, 443, 8080, 8443):
                    req = f"HEAD / HTTP/1.1\r\nHost: {target_ip_or_domain}\r\nConnection: close\r\n\r\n"
                    try:
                        sock.sendall(req.encode("utf-8"))
                        response = sock.recv(1024).decode("utf-8", errors="ignore")
                        for line in response.split("\r\n"):
                            if line.lower().startswith("server:"):
                                port_info["banner"] = line.split(":", 1)[1].strip()
                                break
                    except socket.error:
                        pass
        except socket.error as e:
            logger.debug(f"Socket error on {target_ip_or_domain}:{port} - {e}")
        finally:
            sock.close()

        results["ports"].append(port_info)

    return results


def launch_containerized_webapp_audit(
    target_url: str,
    output_volume_path: str,
    report_filename: str = "zap_report.json",
    timeout_seconds: int = 600
) -> bool:
    """
    Programmatically orchestrates a headless OWASP ZAP baseline scan container.
    Enforces a strict runtime timeout and guarantees cleanup of container resources.
    """
    # Validate target scheme
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Target URL must have http:// or https:// scheme.")

    os.makedirs(output_volume_path, exist_ok=True)

    try:
        import docker
        from docker.errors import DockerException, ContainerError, APIError
    except ImportError:
        logger.error("The 'docker' Python package is required. Install with: pip install docker")
        return False

    try:
        client = docker.from_env()
    except DockerException as e:
        logger.error(f"Failed to initialize Docker client: {e}")
        return False

    image_name = "ghcr.io/zaproxy/zaproxy:stable"
    container = None

    try:
        # Verify or pull image
        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {image_name}...")
            client.images.pull(image_name)

        # Run non-destructive ZAP baseline scan
        logger.info(f"Launching containerized scan against: {target_url}")
        container = client.containers.run(
            image=image_name,
            command=[
                "zap-baseline.py",
                "-t", target_url,
                "-J", report_filename,
                "-I"  # Prevent container non-zero exit on warnings
            ],
            volumes={
                os.path.abspath(output_volume_path): {
                    "bind": "/zap/wrk",
                    "mode": "rw"
                }
            },
            detach=True,
            remove=False,
            network_mode="bridge"
        )

        # Block until completion or timeout
        response = container.wait(timeout=timeout_seconds)
        status_code = response.get("StatusCode", -1)
        logger.info(f"Scan finished with status code: {status_code}")

        report_file = os.path.join(output_volume_path, report_filename)
        return os.path.isfile(report_file)

    except docker.errors.ContainerError as ce:
        logger.error(f"Container runtime error: {ce}")
        return False
    except (docker.errors.APIError, Exception) as err:
        logger.error(f"Execution failed or timed out after {timeout_seconds}s: {err}")
        return False
    finally:
        # Guarantee removal of temporary container resources
        if container:
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(force=True)
                logger.info("Temporary scanner container removed.")
            except Exception as rem_err:
                logger.warning(f"Failed to remove container: {rem_err}")
