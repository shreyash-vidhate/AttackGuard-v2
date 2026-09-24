import ipaddress

def check_ip_reputation(ip_address):
    if not ip_address or ip_address in ["0.0.0.0", "UNKNOWN"]:
        return "UNKNOWN ASSET"

    if ip_address in ["127.0.0.1", "localhost", "::1"]:
        return "Loopback / Localhost"

    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return f"Internal Asset ({ip_address})"
        return f"CLEAN (Public IP: {ip_address})"
    except ValueError:
        return "INVALID IP FORMAT"

run_threat_intel_enrichment = check_ip_reputation