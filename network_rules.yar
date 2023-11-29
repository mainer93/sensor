rule HTTPRule {
    strings:
        $http_string = "GET /index.html HTTP/1.1"
    condition:
        $http_string
}

rule IPRule {
    strings:
        $src_ip = "192.168.1.2"
        $dst_ip = "8.8.8.8"
        $version_ip = "4"
    condition:
        $src_ip or $dst_ip or $version_ip
}

rule TCPRule {
    strings:
        $tcp_string = "TCP"
    condition:
        $tcp_string
}

rule UDPRule {
    strings:
        $udp_string = "UDP"
    condition:
        $udp_string
}

rule ARPRule {
    strings:
        $arp_string = "ARP"
    condition:
        $arp_string
}