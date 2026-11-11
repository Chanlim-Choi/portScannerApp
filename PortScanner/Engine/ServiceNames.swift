import Foundation

/// Common service names by TCP port. A short built-in table for now; the full
/// nmap-services list can replace it later.
enum ServiceNames {
    static func name(for port: UInt16) -> String {
        table[port] ?? ""
    }

    private static let table: [UInt16: String] = {
        var result: [UInt16: String] = [:]
        for line in raw.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let port = UInt16(parts[0]) else { continue }
            result[port] = String(parts[1])
        }
        return result
    }()

    private static let raw = """
    1 tcpmux
    7 echo
    9 discard
    13 daytime
    17 qotd
    19 chargen
    20 ftp-data
    21 ftp
    22 ssh
    23 telnet
    25 smtp
    26 rsftp
    37 time
    43 whois
    49 tacacs
    53 domain
    70 gopher
    79 finger
    80 http
    81 hosts2-ns
    88 kerberos-sec
    106 pop3pw
    110 pop3
    111 rpcbind
    113 ident
    119 nntp
    135 msrpc
    139 netbios-ssn
    143 imap
    144 news
    161 snmp
    179 bgp
    199 smux
    389 ldap
    427 svrloc
    443 https
    444 snpp
    445 microsoft-ds
    464 kpasswd5
    465 smtps
    500 isakmp
    513 login
    514 shell
    515 printer
    543 klogin
    544 kshell
    548 afp
    554 rtsp
    587 submission
    593 http-rpc-epmap
    631 ipp
    636 ldapssl
    646 ldp
    873 rsync
    902 vmware-auth
    990 ftps
    993 imaps
    995 pop3s
    1025 NFS-or-IIS
    1026 LSA-or-nterm
    1027 IIS
    1029 ms-lsa
    1080 socks
    1110 nfsd-status
    1194 openvpn
    1433 ms-sql-s
    1434 ms-sql-m
    1521 oracle
    1720 h323q931
    1723 pptp
    1755 wms
    1883 mqtt
    1900 upnp
    2000 cisco-sccp
    2001 dc
    2049 nfs
    2121 ccproxy-ftp
    2222 ssh-alt
    2375 docker
    2376 docker-tls
    2717 pn-requester
    3000 ppp
    3128 squid-http
    3260 iscsi
    3268 globalcatLDAP
    3269 globalcatLDAPssl
    3283 netassistant
    3306 mysql
    3389 ms-wbt-server
    3689 daap
    3986 mapper-ws_ethd
    4444 krb524
    4899 radmin
    5000 upnp
    5001 commplex-link
    5009 airport-admin
    5051 ida-agent
    5060 sip
    5061 sip-tls
    5101 admdog
    5190 aol
    5222 xmpp-client
    5357 wsdapi
    5432 postgresql
    5555 adb
    5631 pcanywheredata
    5666 nrpe
    5672 amqp
    5800 vnc-http
    5900 vnc
    5901 vnc-1
    5985 wsman
    5986 wsmans
    6000 X11
    6001 X11:1
    6379 redis
    6443 kubernetes-api
    6667 irc
    7000 airplay
    7070 realserver
    7100 font-service
    8000 http-alt
    8008 http
    8009 ajp13
    8080 http-proxy
    8081 blackice-icecap
    8086 influxdb
    8088 radan-http
    8123 polipo
    8443 https-alt
    8554 rtsp-alt
    8883 secure-mqtt
    8888 sun-answerbook
    9000 cslistener
    9090 zeus-admin
    9100 jetdirect
    9200 elasticsearch
    9418 git
    9999 abyss
    10000 snet-sensor-mgmt
    11211 memcache
    27017 mongod
    32400 plex
    32768 filenet-tms
    62078 iphone-sync
    """
}
