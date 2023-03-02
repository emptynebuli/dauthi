package xenmobile

import (
	"fmt"
	"strings"
	"time"

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
  XenMobile Options:
    -a                     User-Agent for request [default: CitrixReceiver/com.zenprise build/22.11.0 Android/11 VpnCapable X1Class]

    -email                 User Email address
  `

	// Methods are available tool methods
	Methods = `
  XenMobile Methods:
    disco                  XenMobile endpoint discovery query
    prof                   Profile the XenMobile provisioning details
    auth                   XenMobile user based authentication
	`

	discoveryAPI  = `https://discovery.cem.cloud.us/ads/root/domain/%s/`
	getServerInfo = `https://%s/zdm/cxf/public/getserverinfo`
	checkLogin    = `https://%s/zdm/cxf/checklogin`

	POSTcheckLogin = `login=%s&password=%s&isAvengerEnabled=false&isEmmCapable=true`
)

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "CitrixReceiver/com.zenprise build/22.11.0 Android/11 VpnCapable X1Class"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("xenmobile")

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
	m.cycle.api.Name = `discoveryAPI`
	m.cycle.api.URL = fmt.Sprintf(discoveryAPI, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
		return
	}

	m.validate()
}

func (m *mdma) prof() {
	m.cycle.api.Name = `getServerInfo`
	m.cycle.api.URL = fmt.Sprintf(getServerInfo, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Profile Failed")
		return
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

		target := m.clone() // assign target

		switch m.opts.Method {
		case "auth":
			if line == "" {
				line = target.opts.UserName
			} else {
				target.opts.UserName = line
			}

			target.cycle.api.Name = `checkLogin`
			target.cycle.api.URL = fmt.Sprintf(checkLogin, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(POSTcheckLogin, target.opts.UserName, target.opts.Password)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"application/x-www-form-urlencoded"}}}
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
		m.cycle.api.WebCall()
		if m.cycle.api.Resp.Status == 0 {
			if m.opts.Miss < m.opts.Retry {
				m.opts.Miss++
				m.logr.Infof([]interface{}{m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Retrying Request")
				<-*m.cycle.block
				m.thread()
				return
			}
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "Null Server Response")
		}
		m.validate()

		// Sleep interval through thread loop
		time.Sleep(time.Duration(m.opts.Sleep) * time.Second)
		<-*m.cycle.block
		*m.cycle.buff <- true
	}()
}

func (m *mdma) validate() {
	switch m.opts.Method {
	case "disco":
		var check struct {
			WorkSpace struct {
				URL []struct {
					Value string `json:"url"`
				} `json:"serviceUrls"`
			} `json:"workspace"`
			DomainType string `json:"domainType"`
		}
		if m.parser(&check, "json") {
			return
		}

		if len(check.WorkSpace.URL) > 0 {
			for _, url := range check.WorkSpace.URL {
				m.logr.Successf([]interface{}{url.Value}, "Endpoint Discovery")
			}
		} else {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Failed to identify Endpoints")
		}

	case "prof":
		var check struct {
			Enabled  bool `xml:"result>serverInfo>enrollmentConfig>enrollmentEnabled"`
			PIN      bool `xml:"result>serverInfo>enrollmentConfig>enrollmentPIN"`
			Password bool `xml:"result>serverInfo>enrollmentConfig>enrollmentPassword"`
			Type     int  `xml:"result>serverInfo>enrollmentConfig>enrollmentType"`
			User     bool `xml:"result>serverInfo>enrollmentConfig>enrollmentUsername"`
		}
		if m.parser(&check, "xml") {
			return
		}

		if check.Enabled {
			m.logr.Successf([]interface{}{check.Type}, "Enrollment Enabled")
		} else {
			m.logr.Failf([]interface{}{check.Type}, "Enrollment Disabled")
		}
		if check.PIN {
			m.logr.Successf([]interface{}{check.Type}, "PIN Authentication Enabled")
		}
		if check.Password {
			m.logr.Successf([]interface{}{check.Type}, "Password Authentication Enabled")
		}
		if check.User {
			m.logr.Successf([]interface{}{check.Type}, "Username Authentication Enabled")
		}

	case "auth":
		var check struct {
			Answer bool `json:"result>checkLogin>answer"`
		}
		if m.parser(&check, "json") {
			return
		}

		if check.Answer {
			m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Successful")
			return
		}
		m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Failed")

	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	switch m.opts.Method {
	case "disco":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Endpoint required")
		}
		m.disco()

	case "prof":
		if m.opts.Endpoint == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Endpoint required")
			return
		}
		m.prof()

	case "auth":
		if (m.opts.UserName == "" && m.opts.File == "") || m.opts.Password == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "User/Password or File/Password required")
			return
		}
		m.auth()

	default:
		m.logr.StdOut(Methods)
		m.logr.Fatalf(nil, "Invalid Method Selected %v", m.opts.Method)
	}
}
