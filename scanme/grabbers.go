package scanme

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GetHeader(ipAddress string, port int) (string, error) {
	req, err := net.DialTimeout("tcp", ipAddress+":"+strconv.Itoa(port), 1*time.Second)
	if err != nil {
		return "", err
	}
	defer req.Close()

	_, err = req.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(req)
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
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ipAddress, port), tlsConfig)

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
	case 6667: // IRC
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