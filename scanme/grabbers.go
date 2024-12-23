package scanme

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
)

func GetHeader(ipAddress string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", ipAddress+":"+strconv.Itoa(port), 1*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Establishing TLS connection for HTTPS (port 443)
	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, // InsecureSkipVerify is used here for simplicity
		})
		if err := tlsConn.Handshake(); err != nil {
			return "", err
		}
		conn = tlsConn
	}

	// Sending HTTP request
	_, err = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		if strings.HasPrefix(line, "Server:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Server:")), nil
		}
	}
}

func GrabMysqlBanner(ipAddress string, port int) (string, error) {
	req, err := net.DialTimeout("tcp", ipAddress+":"+strconv.Itoa(port), 1*time.Second)
	if err != nil {
		return "", err
	}
	defer req.Close()
	buf := make([]byte, 1024)

	re := regexp.MustCompile(".+\x0a([^\x00]+)\x00.+")
	read, err := req.Read(buf)

	if err != nil {
		return "", err
	}
	serviceBanner := string(buf[:read])
	match := re.FindStringSubmatch(serviceBanner)

	if len(match) > 0 {
		return match[1], nil
	}
	return "", nil
}

func GetLDAPBanner(ipAddress string, port int) (string, error) {
	ldapURL := fmt.Sprintf("ldaps://%s:%d", ipAddress, port)
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return "", err
	}
	defer l.Close()

	// Bind to the LDAP server with an empty password
	err = l.UnauthenticatedBind("")
	if err != nil {
		return "", err
	}

	// Search for server information in the root DSE
	searchRequest := ldap.NewSearchRequest(
		"",                   // base dn (root DSE)
		ldap.ScopeBaseObject, // search scope (base object)
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedLDAPVersion", "defaultNamingContext", "*"}, nil,
	)

	searchResult, err := l.Search(searchRequest)
	if err != nil {
		return "", err
	}

	// Format server information
	var serverInfo string
	for _, entry := range searchResult.Entries {
		for _, attr := range entry.Attributes {
			serverInfo += fmt.Sprintf("%s: %s", attr.Name, attr.Values)
		}
	}

	return serverInfo, nil
}

func GetDNSBanner(ipAddress string, port int) (string, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Name: "version.bind.", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}

	addr := fmt.Sprintf("%s:%d", ipAddress, port)
	in, _, err := c.Exchange(m, addr)
	if err != nil {
		return "", err
	}

	if in != nil && len(in.Answer) > 0 {
		s := in.Answer[0].String()
		re := regexp.MustCompile(".*\"([^\"]+)\".*")
		match := re.FindStringSubmatch(s)
		if len(match) > 0 {
			return match[1], nil
		}
	}

	return "", nil
}

func GrabBanner(ipAddress string, port int) string {
	switch port {
	case 21: // FTP
	case 22: // SSH
	case 25: // SMTP
	case 110: // POP
	case 119: // NNTP
	case 143: // IMAP
	case 636: // LDAPS
		serverInfo, err := GetLDAPBanner(ipAddress, port)
		if err != nil {
			return ""
		}
		return serverInfo
	case 3306: // MYSQL
		mysqlBanner, err := GrabMysqlBanner(ipAddress, port)
		if err != nil {
			return ""
		}
		return mysqlBanner
	case 80: // HTTP
		serverHeader, err := GetHeader(ipAddress, port)
		if err != nil {
			return ""
		}
		return serverHeader
	case 443: // HTTPS
		serverHeader, err := GetHeader(ipAddress, port)
		if err != nil {
			return ""
		}
		return serverHeader
	case 6667: // IRC
	case 53: // DNS
		dnsBanner, err := GetDNSBanner(ipAddress, port)
		if err != nil {
			return ""
		}
		return dnsBanner
	default:
		return ""
	}

	req, err := net.DialTimeout("tcp", ipAddress+":"+strconv.Itoa(port), 1*time.Second)
	if err != nil {
		return ""
	}
	defer req.Close()

	read, err := bufio.NewReader(req).ReadString('\n')
	if err != nil {
		return ""
	}

	serviceBanner := strings.Trim(read, "\r\n\t ")
	return serviceBanner
}
