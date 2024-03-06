package scanme

import (
	"bufio"
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

func GrabBanner(ipAddress string, port int) string {
	switch port {
	case 21: // FTP
	case 22: // SSH
	case 25: // SMTP
	case 110: // POP
	case 119: // NNTP
	case 143: // IMAP
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
