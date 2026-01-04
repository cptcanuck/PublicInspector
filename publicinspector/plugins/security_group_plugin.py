"""EC2 Security Group public access scanner plugin."""

from publicinspector.aws_base_plugin import AWSBasePlugin


class SecurityGroupPlugin(AWSBasePlugin):
    """Scans EC2 Security Groups for overly permissive public access rules."""
    
    def get_name(self):
        """Return plugin name."""
        return "Security Group Scanner"
    
    def get_service_name(self):
        """Return service name."""
        return "ec2_security_groups"
    
    def scan(self):
        """
        Scan security groups for public access rules.
        
        Returns:
            List of findings
        """
        findings = []
        
        # Get all regions to scan
        regions = self.get_all_regions()
        
        for region in regions:
            try:
                region_findings = self._scan_region(region)
                findings.extend(region_findings)
            except Exception as e:
                print(f"Error scanning security groups in {region}: {e}")
        
        return findings
    
    def _scan_region(self, region):
        """
        Scan security groups in a specific region.
        
        Args:
            region: AWS region name
            
        Returns:
            List of findings for this region
        """
        findings = []
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Get all security groups
            response = ec2.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            for sg in security_groups:
                sg_findings = self._check_security_group(sg, region)
                findings.extend(sg_findings)
                
        except Exception as e:
            # Skip regions we can't access
            pass
        
        return findings
    
    def _check_security_group(self, sg, region):
        """
        Check a security group for public access rules.
        
        Args:
            sg: Security group details
            region: AWS region
            
        Returns:
            List of findings for this security group
        """
        findings = []
        sg_id = sg.get('GroupId', 'unknown')
        sg_name = sg.get('GroupName', 'unknown')
        
        # Check ingress rules
        ingress_rules = sg.get('IpPermissions', [])
        
        for rule in ingress_rules:
            public_ips = []
            
            # Check IPv4 ranges
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    public_ips.append('0.0.0.0/0 (all IPv4)')
            
            # Check IPv6 ranges
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6', '')
                if cidr == '::/0':
                    public_ips.append('::/0 (all IPv6)')
            
            # If public access found, create a finding
            if public_ips:
                from_port = rule.get('FromPort', 'all')
                to_port = rule.get('ToPort', 'all')
                protocol = rule.get('IpProtocol', 'all')
                
                if protocol == '-1':
                    protocol = 'all'
                
                # Determine severity based on ports
                severity = self._determine_severity(from_port, to_port, protocol)
                
                finding = {
                    'resource_type': 'security_group',
                    'resource_id': sg_id,
                    'resource_name': sg_name,
                    'public_access': f'Allows inbound from {", ".join(public_ips)}',
                    'region': region,
                    'account_id': self.account_id,
                    'severity': severity,
                    'details': {
                        'security_group_id': sg_id,
                        'security_group_name': sg_name,
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'public_cidrs': public_ips
                    }
                }
                findings.append(finding)
        
        return findings
    
    def _determine_severity(self, from_port, to_port, protocol):
        """
        Determine severity based on port and protocol.
        
        Args:
            from_port: Starting port
            to_port: Ending port
            protocol: Protocol
            
        Returns:
            Severity string
        """
        # All ports/protocols open is critical
        if protocol == 'all' or (from_port == 'all' and to_port == 'all'):
            return 'critical'
        
        # Common risky ports
        risky_ports = [22, 3389, 3306, 5432, 27017, 6379, 1433]
        
        try:
            from_port_int = int(from_port)
            to_port_int = int(to_port)
            
            for risky_port in risky_ports:
                if from_port_int <= risky_port <= to_port_int:
                    return 'high'
        except (ValueError, TypeError):
            pass
        
        # HTTP/HTTPS is lower risk
        if (from_port == 80 or from_port == 443) and (to_port == 80 or to_port == 443):
            return 'low'
        
        return 'medium'
