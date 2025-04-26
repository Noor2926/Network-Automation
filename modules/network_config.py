from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection  # type: ignore
import xml.etree.ElementTree as ET
import logging

# Configure logging to integrate with Flask app's logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ansible_network_config")

def build_xml_config(hostname=None, interface=None, ntp_server=None, use_dhcp=False):
    """
    Build NETCONF XML configuration for hostname, interface, and NTP settings.
    Supports DHCP for interface configuration, tailored for Nokia SR OS.
    """
    try:
        config = ET.Element("config", xmlns="urn:ietf:params:xml:ns:netconf:base:1.0")
        
        # System configuration
        system = ET.SubElement(config, "system", xmlns="urn:ietf:params:xml:ns:yang:ietf-system")
        
        # Set hostname
        if hostname:
            host_name = ET.SubElement(system, "host-name")
            host_name.text = hostname
        
        # Configure NTP
        if ntp_server:
            ntp = ET.SubElement(system, "ntp")
            enabled = ET.SubElement(ntp, "enabled")
            enabled.text = "true"
            server = ET.SubElement(ntp, "server")
            name = ET.SubElement(server, "name")
            name.text = ntp_server
            udp = ET.SubElement(server, "udp")
            address = ET.SubElement(udp, "address")
            address.text = ntp_server
        
        # Interface configuration for Nokia SR OS
        if interface:
            interfaces = ET.SubElement(config, "configure", xmlns="urn:nokia.com:sros:ns:yang:sr:conf")
            port = ET.SubElement(interfaces, "port")
            port_id = ET.SubElement(port, "port-id")
            port_id.text = interface.get("name", "1/1/1")
            description = ET.SubElement(port, "description")
            description.text = interface.get("description", "Configured by Ansible")
            
            if use_dhcp:
                ip = ET.SubElement(port, "ip")
                dhcp = ET.SubElement(ip, "dhcp")
                client = ET.SubElement(dhcp, "client")
                client.text = "true"
            elif "ipv4_address" in interface:
                ip = ET.SubElement(port, "ip")
                address = ET.SubElement(ip, "address")
                ip_addr = ET.SubElement(address, "ip-address")
                ip_addr.text = interface["ipv4_address"]
                mask = ET.SubElement(address, "mask")
                mask.text = interface.get("subnet_mask", "255.255.255.255")
        
        logger.info("Built NETCONF XML configuration successfully")
        return ET.tostring(config, encoding="unicode")
    except Exception as e:
        logger.error(f"Failed to build XML configuration: {str(e)}")
        raise

def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(type="str", required=False),
            interface=dict(
                type="dict",
                required=False,
                options=dict(
                    name=dict(type="str", required=True),
                    description=dict(type="str"),
                    ipv4_address=dict(type="str"),
                    subnet_mask=dict(type="str")
                )
            ),
            ntp_server=dict(type="str", required=False),
            use_dhcp=dict(type="bool", default=False),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            backup=dict(type="bool", default=False),
            backup_options=dict(
                type="dict",
                required=False,
                options=dict(
                    filename=dict(type="str"),
                    dir_path=dict(type="str")
                )
            )
        ),
        supports_check_mode=True
    )
    
    result = {"changed": False, "warnings": []}
    
    # Get parameters
    hostname = module.params["hostname"]
    interface = module.params["interface"]
    ntp_server = module.params["ntp_server"]
    use_dhcp = module.params["use_dhcp"]
    state = module.params["state"]
    backup = module.params["backup"]
    backup_options = module.params["backup_options"]
    
    # Validate inputs
    if not any([hostname, interface, ntp_server]):
        module.fail_json(msg="At least one of hostname, interface, or ntp_server must be provided.")
    
    if use_dhcp and interface and "ipv4_address" in interface:
        module.fail_json(msg="Cannot specify both DHCP and static IPv4 address for interface.")
    
    # Build XML configuration
    try:
        xml_config = build_xml_config(hostname, interface, ntp_server, use_dhcp)
    except Exception as e:
        module.fail_json(msg=f"Failed to build XML configuration: {str(e)}")
    
    # Initialize connection
    try:
        connection = Connection(module._socket_path)
        logger.info("Initialized NETCONF connection")
    except Exception as e:
        module.fail_json(msg=f"Failed to initialize NETCONF connection: {str(e)}")
    
    # Backup configuration
    if backup:
        backup_params = {}
        if backup_options:
            if backup_options.get("filename"):
                backup_params["filename"] = backup_options["filename"]
            if backup_options.get("dir_path"):
                backup_params["dir_path"] = backup_options["dir_path"]
        try:
            backup_response = connection.get_config(source="running", filter=None)
            result["backup"] = backup_response
            if backup_params:
                module.backup_config(backup_response, **backup_params)
            logger.info("Configuration backup completed")
        except Exception as e:
            result["warnings"].append(f"Backup failed: {str(e)}")
            logger.warning(f"Backup failed: {str(e)}")
    
    # Apply configuration
    if state == "present":
        try:
            response = connection.edit_config(config=xml_config, target="candidate", commit=True)
            result["changed"] = True
            result["response"] = response
            logger.info("Configuration applied successfully")
        except Exception as e:
            logger.error(f"Failed to apply configuration: {str(e)}")
            module.fail_json(msg=f"Failed to apply configuration: {str(e)}")
    elif state == "absent":
        if ntp_server:
            try:
                xml_config = build_xml_config(ntp_server=ntp_server)
                root = ET.fromstring(xml_config)
                ntp = root.find(".//{urn:ietf:params:xml:ns:yang:ietf-system}ntp")
                if ntp is not None:
                    ntp.find("enabled").text = "false"
                    server = ntp.find("server")
                    if server is not None:
                        server.set("operation", "remove")
                xml_config = ET.tostring(root, encoding="unicode")
                response = connection.edit_config(config=xml_config, target="candidate", commit=True)
                result["changed"] = True
                result["response"] = response
                logger.info("Configuration removed successfully")
            except Exception as e:
                logger.error(f"Failed to remove configuration: {str(e)}")
                module.fail_json(msg=f"Failed to remove configuration: {str(e)}")
    
    module.exit_json(**result)

if __name__ == "__main__":
    main()