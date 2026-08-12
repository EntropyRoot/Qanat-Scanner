#include "qanat/task.h"

typedef struct {
    uint16_t    port;
    const char *name;
} svc;

/* The port-sorted table uses binary search because hashing would not help at this size. */
static const svc kServices[] = {
    { 7, "echo" },          { 19, "chargen" },     { 20, "ftp-data" },
    { 21, "ftp" },          { 22, "ssh" },         { 23, "telnet" },
    { 25, "smtp" },         { 43, "whois" },       { 49, "tacacs" },
    { 53, "domain" },       { 67, "dhcps" },       { 68, "dhcpc" },
    { 69, "tftp" },         { 70, "gopher" },      { 79, "finger" },
    { 80, "http" },         { 88, "kerberos" },    { 102, "iso-tsap" },
    { 110, "pop3" },        { 111, "rpcbind" },    { 113, "ident" },
    { 119, "nntp" },        { 123, "ntp" },        { 135, "msrpc" },
    { 137, "netbios-ns" },  { 138, "netbios-dgm" },{ 139, "netbios-ssn" },
    { 143, "imap" },        { 161, "snmp" },       { 162, "snmptrap" },
    { 179, "bgp" },         { 194, "irc" },        { 389, "ldap" },
    { 427, "svrloc" },      { 443, "https" },      { 445, "microsoft-ds" },
    { 465, "smtps" },       { 500, "isakmp" },     { 512, "exec" },
    { 513, "login" },       { 514, "shell" },      { 515, "printer" },
    { 520, "route" },       { 543, "klogin" },     { 544, "kshell" },
    { 548, "afp" },         { 554, "rtsp" },       { 587, "submission" },
    { 631, "ipp" },         { 636, "ldaps" },      { 646, "ldp" },
    { 873, "rsync" },       { 902, "vmware" },     { 989, "ftps-data" },
    { 990, "ftps" },        { 993, "imaps" },      { 995, "pop3s" },
    { 1080, "socks" },      { 1194, "openvpn" },   { 1352, "lotusnotes" },
    { 1433, "mssql" },      { 1521, "oracle" },    { 1701, "l2tp" },
    { 1723, "pptp" },       { 1883, "mqtt" },      { 1900, "upnp" },
    { 2049, "nfs" },        { 2082, "cpanel" },    { 2083, "cpanel-ssl" },
    { 2086, "whm" },        { 2087, "whm-ssl" },   { 2095, "webmail" },
    { 2096, "webmail-ssl" },{ 2181, "zookeeper" }, { 2222, "ssh-alt" },
    { 2375, "docker" },     { 2376, "docker-tls" },{ 3000, "http-dev" },
    { 3128, "squid" },      { 3260, "iscsi" },     { 3306, "mysql" },
    { 3389, "rdp" },        { 3690, "svn" },       { 4444, "krb524" },
    { 4500, "ipsec-nat" },  { 4567, "tram" },      { 5000, "upnp-http" },
    { 5060, "sip" },        { 5061, "sip-tls" },   { 5222, "xmpp-client" },
    { 5269, "xmpp-server" },{ 5353, "mdns" },      { 5432, "postgresql" },
    { 5555, "freeciv" },    { 5601, "kibana" },    { 5672, "amqp" },
    { 5800, "vnc-http" },   { 5900, "vnc" },       { 5938, "teamviewer" },
    { 5984, "couchdb" },    { 6000, "x11" },       { 6379, "redis" },
    { 6443, "kubernetes" }, { 6667, "irc" },       { 6881, "bittorrent" },
    { 7001, "weblogic" },   { 7070, "realserver" },{ 8000, "http-alt" },
    { 8006, "proxmox" },    { 8008, "http-alt" },  { 8009, "ajp13" },
    { 8080, "http-proxy" }, { 8081, "http-alt" },  { 8086, "influxdb" },
    { 8088, "radan-http" }, { 8090, "http-alt" },  { 8123, "homeassistant" },
    { 8443, "https-alt" },  { 8500, "consul" },    { 8686, "sun-as-jmx" },
    { 8888, "http-alt" },   { 9000, "cslistener" },{ 9001, "tor-orport" },
    { 9042, "cassandra" },  { 9090, "prometheus" },{ 9091, "transmission" },
    { 9092, "kafka" },      { 9100, "jetdirect" }, { 9200, "elasticsearch" },
    { 9300, "elastic-node" },{ 9418, "git" },      { 9999, "abyss" },
    { 10000, "webmin" },    { 11211, "memcached" },{ 15672, "rabbitmq-mgmt" },
    { 16379, "redis-cluster" }, { 27017, "mongodb" }, { 27018, "mongodb-shard" },
    { 28017, "mongodb-http" },  { 32400, "plex" },    { 33060, "mysqlx" },
    { 50000, "db2" },       { 51820, "wireguard" },{ 54321, "posix-rpc" },
};

const char *qn_service_name(uint16_t port)
{
    uint32_t lo = 0, hi = (uint32_t)(sizeof kServices / sizeof kServices[0]);

    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        if (kServices[mid].port == port)
            return kServices[mid].name;
        if (kServices[mid].port < port)
            lo = mid + 1;
        else
            hi = mid;
    }
    return "";
}

static const uint16_t kTop[] = {
    80,   443,  22,   21,   25,   3389, 110,  445,  139,  143,  53,   135,
    3306, 8080, 1723, 111,  995,  993,  5900, 23,   587,  8443, 1433, 5432,
    6379, 27017,8888, 9200, 2222, 8000, 8081, 10000,5060, 1194, 1080, 3128,
    2082, 2083, 2086, 2087, 7070, 9000, 9090, 5555, 6443, 11211,161,  389,
    636,  873,  2049, 5672, 9092, 15672,32400,51820,
};

const uint16_t *qn_top_ports(uint32_t *count)
{
    *count = (uint32_t)(sizeof kTop / sizeof kTop[0]);
    return kTop;
}
