<p align="center">
  <img height="500px" src="images/dauthi.jpg">
</p>

## Description
**Dauthi** is a tool designed to perform authentication attacks against various Mobile Device Management (MDM) solutions. This tool represents the evolutionary growth from my original research on [airCross](https://github.com/emptynebuli/airCross) and [rustyIron](https://github.com/emptynebuli/rustyIron). Unlike these past examples, Dauthi is build with a dedicated class for each framework. this allows for the tool to scale and meet the demands of various MDM tools and platforms.

## Usage
```
     ;                                                               
     ED.                                                             
     E#Wi                     :                                   
     E###G.                   Ef                 .    .       t  
     E#fD#W;              ..  E#t     GEEEEEEEL  Di   Dt      Ej 
     E#t t##L            ;W,  E#t     ,;;L#K;;.  E#i  E#i     E#,
     E#t  .E#K,         j##,  E#t        t#E     E#t  E#t     E#t
     E#t    j##f       G###,  E#t fi     t#E     E#t  E#t     E#t
     E#t    :E#K:    :E####,  E#t L#j    t#E     E########f.  E#t
     E#t   t##L     ;W#DG##,  E#t L#L    t#E     E#j..K#j...  E#t
     E#t .D#W;     j###DW##,  E#tf#E:    t#E     E#t  E#t     E#t
     E#tiW#G.     G##i,,G##,  E###f      t#E     E#t  E#t     E#t
     E#K##i     :K#K:   L##,  E#K,       t#E     f#t  f#t     E#t
     E##D.     ;##D.    L##,  EL          fE      ii   ii     E#t
     E#t       ,,,      .,,   :            :                  ,;.
     L:                                                          
                                                   @emptynebuli
      
  Usage:
    dauthi <charge> <method> [OPTIONS] <dom/corpid/endpoint/cipherTXT> <file>
    dauthi [charge] -h | -help
    dauthi -v

  Global Options:
    -d                     Enable debug output (incremental -ddd)
    -h, -help              Show usage
    -hh                    Extended help
    -p                     User password value
    -r                     Disable randomize device ID
    -s                     Silent - disable banner output
    -t                     Application threads [default: 10]
    -u                     Username value
    -v, -version           Version details

    -proxy                 SOCKS5 proxy IP and port for traffic tunneling (aka 127.0.0.1:8081)
    -retry                 Number of retry attempts on failed connections [default: 1]
    -sleep                 Sleep timer per thread groups in Seconds (aka 3)
    -uuid                  Device UUID value

    <dom>                  Target FQDN for Discovery
    <endpoint>             MDM Authentication Endpoint
    <cipherTXT>            Encrypted CipherTXT
    <file>                 Line divided file containing brute-force values
 
  dauthi Charges:
    disco                  Global discovery of all charges

    airwatch               VMWare AirWatch
    blackberry             BlackBerry UEM
    intune                 Microsoft Intune
    mfa                    Various MFA Authenticators
    mobileiron             Ivanti MobileIron
    xenmobile              Citrix XenMobile

```

Depending on the `charge` that is selected different *sub* command options will become available. The below example shows the `AirWatch` charge options:

```$ dauthi airwatch -s

  Usage:
    dauthi <charge> <method> [OPTIONS] <dom/corpid/endpoint/cipherTXT> <file>
    dauthi [charge] -h | -help
    dauthi -v

  Global Options:
    -d                     Enable debug output (incremental -ddd)
    -h, -help              Show usage
    -hh                    Extended help
    -p                     User password value
    -r                     Disable randomize device ID
    -s                     Silent - disable banner output
    -t                     Application threads [default: 10]
    -u                     Username value
    -v, -version           Version details

    -proxy                 SOCKS5 proxy IP and port for traffic tunneling (aka 127.0.0.1:8081)
    -retry                 Number of retry attempts on failed connections [default: 1]
    -sleep                 Sleep timer per thread groups in Seconds (aka 3)
    -uuid                  Device UUID value

    <dom>                  Target FQDN for Discovery
    <endpoint>             MDM Authentication Endpoint
    <cipherTXT>            Encrypted CipherTXT
    <file>                 Line divided file containing brute-force values
 
  AirWatch Options:
    -a                     User-Agent [default: Agent/20.08.0.23/Android/11]

    -email                 Target email
    -gid                   AirWatch GroupID Value
    -sgid                  AirWatch sub-GroupID Value
    -sint                  AirWatch sub-GroupID INT value (Associated to multiple groups)
  
  AirWatch Methods:
    disco                  GroupID discovery query
    prof                   GroupID validation query
    enum-gid               GroupID brute-force enumeration
    auth-box-login         Boxer login SFA attack (Requires Email)
    auth-box-reg           Boxer MDM registration SFA attack (Requires Email)
    auth-box-lgid          Boxer login SFA attack w/ multi-group tenants
    auth-val               AirWatch single-factor credential validation attack

```

Executing the `disco` charge will run discovery against all available charges. This is helpful to determine what MDM solutions a domain maybe hosting.

```
$ dauthi disco microsoft.com

     ;                                                               
     ED.                                                             
     E#Wi                     :                                   
     E###G.                   Ef                 .    .       t  
     E#fD#W;              ..  E#t     GEEEEEEEL  Di   Dt      Ej 
     E#t t##L            ;W,  E#t     ,;;L#K;;.  E#i  E#i     E#,
     E#t  .E#K,         j##,  E#t        t#E     E#t  E#t     E#t
     E#t    j##f       G###,  E#t fi     t#E     E#t  E#t     E#t
     E#t    :E#K:    :E####,  E#t L#j    t#E     E########f.  E#t
     E#t   t##L     ;W#DG##,  E#t L#L    t#E     E#j..K#j...  E#t
     E#t .D#W;     j###DW##,  E#tf#E:    t#E     E#t  E#t     E#t
     E#tiW#G.     G##i,,G##,  E###f      t#E     E#t  E#t     E#t
     E#K##i     :K#K:   L##,  E#K,       t#E     f#t  f#t     E#t
     E##D.     ;##D.    L##,  EL          fE      ii   ii     E#t
     E#t       ,,,      .,,   :            :                  ,;.
     L:                                                          
                                                   @emptynebuli
     
[*] [airwatch] [disco] Using sample email: dave@microsoft.com
[+] [airwatch] [dmp.nokia.com] Endpoint Discovery
[+] [airwatch] [Nokia] GroupID Discovery
[-] [mobileiron] [microsoft.com] Discovery Failed
[-] [xenmobile] [microsoft.com] Discovery Failed
[*] [blackberry] [disco] Using sample email: dave@microsoft.com
[-] [blackberry] [microsoft.com] Discovery Failed
```

As an additional plus, I have pulled some functionality from [TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) within the `intune` charge. These options can be used to pull tenant values from 0365 and identify other domains an organization may be hosting.

```
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
```

```
$ dauthi intune disco-tenant -s github.com
[*] [intune] [8] o365 Tenant(2) Identified
[+] [intune] [MicrosoftEur] Tenant Domain
[+] [intune] [MicrosoftAPC] Tenant Domain
[+] [intune] [msfts2] Tenant Domain
[+] [intune] [msfts2.mail] Tenant Domain
[+] [intune] [microsoftprd] Tenant Domain
[+] [intune] [microsoftcan] Tenant Domain
[+] [intune] [microsoft.mail] Tenant Domain
[+] [intune] [microsoft] Tenant Domain
[*] [intune] [288] o365 Domain(s) Identified
[+] [intune] [munich.microsoft.com] Alias Domain
[+] [intune] [video2brain.com] Alias Domain
[+] [intune] [exchange.microsoft.com] Alias Domain
[+] [intune] [preonboarding.microsoft.com] Alias Domain
[+] [intune] [email2.microsoft.com] Alias Domain
[+] [intune] [fast.no] Alias Domain
...
```

## Charge Template
New charges carry the following basic tempate structure. 

```golang
package <newCharge>

const (
	// Usage details for charge
	Usage = ``

	// Methods are available tool methods
	Methods = ``
)

// Init mdma with default values and return obj
func Init(o utils.ChargeOpts) *mdma {

}

// disco is the discovery function call
func (m *mdma) disco() {

}

// prof is the function call for pulling validation details from the MDM
func (m *mdma) prof() {

}

// auth is the function call for performing authentication functions
func (m *mdma) auth() {

}

// thread is the function call for recursion
func (m *mdma) thread() {

}

// validate is used to validate the return context of a Charge requests
func (m *mdma) validate() {

}

// Call represents the switch function for activating all class methods
func (m *mdma) Call() {

}
```

## Background
* [VMWare Airwatch](https://emptynebuli.github.io/tooling/2020/12/11/aircross.html)
* [Ivanti MobileIron](https://emptynebuli.github.io/tooling/2021/03/22/rustyiron.html)
* [BlackBerry](https://emptynebuli.github.io/tooling/2024/04/22/blackberryMDM.html)

## Credits
* [TREVORspray](https://github.com/blacklanternsecurity/TREVORspray)