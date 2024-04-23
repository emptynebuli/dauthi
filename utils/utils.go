package utils

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"crypto/rand"
	"crypto/tls"

	"net/http"

	"golang.org/x/net/proxy"
)

// CLI options for charge initialization
type ChargeOpts struct {
	Agent       string
	Cookie      string
	CorpID      string
	Debug       int
	Email       string
	Endpoint    string
	File        string
	GUID        int
	GroupID     string
	Method      string
	Miss        int
	PIN         string
	Password    string
	Port        string
	PriKey      string
	Proxy       string
	PubCert     string
	Retry       int
	RUUID       bool
	Sleep       int
	Silent      bool
	SubGroup    string
	SubGroupINT int
	Tenant      string
	Threads     int
	UUID        string
	UserName    string
}

// API is the object structure for utils to make
// client web requests. The Opts option is intended
// for dynamic typing of various HTTP request values
// which may need to be applied to the request or client.
// For example, various HTTP header values
type API struct {
	Name   string
	URL    string
	Data   string
	Method string
	Opts   *map[string]interface{}
	Debug  int
	Log    *Logger
	Base   int
	Offset int
	Proxy  string
	Resp   resp
}

// RESP represents the struct for connection responses
// of HTTP/HTTPS/TCP based connections
type resp struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// RandUUID generates a random UUID.
// Input value is designed to dictate
// how long the returned UUID would be.
// Results are in HEX, so input length
// should be half the required output length.
func RandUUID(size int) string {
	uuid := make([]byte, size)
	io.ReadFull(rand.Reader, uuid)
	return fmt.Sprintf("%x", uuid)
}

func RandGUID() string {
	uuid := RandUUID(18)
	return fmt.Sprintf("%s-%s-%s-%s-%s", uuid[0:8], uuid[9:13], uuid[14:18], uuid[19:23], uuid[24:])
}

func Resolver(host string) bool {
	_, err := net.LookupIP(host)
	return err == nil
}

// ParseJSON(check) is a wrapper for json.Unmarshal
func (r *resp) ParseJSON(check interface{}) error {
	err := json.Unmarshal(r.Body, check)
	if err != nil {
		return err
	}
	return nil
}

// ParseXML(check) is a wrapper for xml.Unmarshal
func (r *resp) ParseXML(check interface{}) error {
	err := xml.Unmarshal(r.Body, check)
	if err != nil {
		return err
	}
	return nil
}

func (api *API) WebCall() {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	// Support proxy connections for web requests
	if api.Proxy != "" {
		socks, err := proxy.SOCKS5("tcp", api.Proxy, nil, &net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			api.Log.Errorf([]interface{}{api.Name}, "Failed to establish SOCKS connection %v", err)
			return
		}
		transport.Dial = socks.Dial
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(api.Method, api.URL, bytes.NewBuffer([]byte(api.Data)))
	if err != nil {
		api.Log.Errorf(nil, "Request Error (%s):  %v", api.URL, err)
		return
	}

	if api.Opts != nil {
		for k, v := range *api.Opts {
			switch k {
			case "Header":
				req.Header = v.(map[string][]string)
			case "CheckRedirect":
				client.CheckRedirect = v.(func(req *http.Request, via []*http.Request) error)
			}
		}
	}

	if api.Debug > 0 {
		api.Log.Debugf([]interface{}{api.Name}, "REQUEST HEADER: %s %s %s", req.URL, req.Proto, req.Header)
		if api.Debug > 1 {
			api.Log.Debugf([]interface{}{api.Name}, "REQUEST BODY: %s", req.Body)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if api.Debug > 0 {
			api.Log.Debugf([]interface{}{api.Name}, "Dial Error: %v", err)
		}
		return
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		api.Log.Errorf([]interface{}{api.Name}, "Unable to read response: %v", err)
	}
	api.Resp.Body = bodyBytes
	api.Resp.Status = resp.StatusCode
	api.Resp.Header = resp.Header

	resp.Body.Close()

	if api.Debug > 1 {
		if api.Debug > 2 {
			api.Log.Debugf([]interface{}{api.Name}, "RESPONSE Status: %v Headers: %v", api.Resp.Status, api.Resp.Header)
		}
		api.Log.Debugf([]interface{}{api.Name}, "RESPONSE BODY: %s", api.Resp.Body)
	}
}

// SocketCall is the function for executing a TLS socket request
func (api *API) SocketTLSDial() {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	var conn *tls.Conn
	// Support TLS Socket connections
	if api.Proxy != "" {
		socks, err := proxy.SOCKS5(api.Method, api.Proxy, nil, proxy.Direct)
		if err != nil {
			api.Log.Fatalf([]interface{}{api.Name}, "Failed to establish SOCKS connection %v", err)
		}
		pcon, err := socks.Dial(api.Method, api.URL)
		if err != nil {
			api.Log.Errorf([]interface{}{api.Name}, "Failed to proxy connection %v", err)
			api.Resp.Status = 400
			return
		}
		conn = tls.Client(pcon, tlsConfig)
	} else {
		var err error
		conn, err = tls.Dial(api.Method, api.URL, tlsConfig)
		if err != nil {
			api.Log.Errorf(nil, "Dial Error: %v", err)
			api.Resp.Status = 400
			return
		}
	}

	buffer := make([]byte, 4096)

	for _, val := range (*api.Opts)["request"].([]string) {
		ibytes, err := io.WriteString(conn, val)
		if err != nil {
			api.Log.Errorf([]interface{}{api.Name}, "Initialization Write Error: %v", err)
			api.Resp.Status = 400
			return
		}
		if api.Debug > 0 {
			api.Log.Debugf([]interface{}{api.Name}, "Submitted %d bytes", ibytes)
			if api.Debug > 1 {
				if api.Offset > len(val) {
					api.Offset = len(val)
				}
				api.Log.Debugf([]interface{}{api.Name}, "POST Message Body\n%s", hexDump([]byte(val)[api.Base:api.Offset]))
			}
		}

		buffer = make([]byte, 4096) // Assign buffer
		rbytes, _ := conn.Read(buffer)
		if api.Debug > 0 {
			api.Log.Debugf([]interface{}{api.Name}, "Received %d bytes", rbytes)
			if api.Debug > 1 {
				api.Log.Debugf([]interface{}{api.Name}, "RESPONSE Message Body\n%s", hexDump(buffer[api.Base:api.Offset]))
			}
		}
	}
	conn.Close()

	api.Resp.Body = buffer
}

// ReadFile opens file for read access and returns a byte slice
// or error
func ReadFile(file string) ([]byte, error) {
	var out []byte
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out, _ = io.ReadAll(f)
	f.Close()
	return out, nil
}

// hexDump takes a byte slice and outputs a hexDump style string
func hexDump(b []byte) string {
	var str string
	for i := 0; i < len(b)-1; i += 8 {
		if (i/8)%2 < 1 {
			str += "   "
		} else {
			str += "  "
		}
		str += fmt.Sprintf("% X", b[i:i+8])
		if (i/8)%2 == 1 {
			str += fmt.Sprintf("  |%s|\n", hex2String(b[i-8:i+8]))
		} else if i+8 > len(b)-1 {
			if (i/8)%2 < 1 {
				str += "  "
			}
			for x := 0; x < (len(b)+1)-i; x++ {
				str += "   "
			}
			str += fmt.Sprintf(" |%s|\n", hex2String(b[i:i+8]))
		}
	}
	return str
}

// hex2String validates a byte array for ASCII printable characters
// and subs '.' otherwise
func hex2String(b []byte) string {
	var str string
	for _, i := range b {
		if i > byte(0x1F) && i < byte(0x7F) {
			str += string(i)
		} else {
			str += "."
		}
	}
	return str
}
