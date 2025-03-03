package wireproxy

import (
    "os"
    "github.com/go-ini/ini"
    "testing"
)

func loadIniConfig(config string) (*ini.File, error) {
    iniOpt := ini.LoadOptions{
    Insensitive:            true,
    AllowShadows:           true,
    AllowNonUniqueSections: true,
    }

    return ini.LoadSources(iniOpt, []byte(config))
}

func TestWireguardConfWithoutSubnet(t *testing.T) {
    const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
    var cfg DeviceConfig
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }

    err = ParseInterface(iniData, &cfg)
    if err != nil {
    t.Fatal(err)
    }
}

func TestWireguardConfWithSubnet(t *testing.T) {
    const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/23
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
    var cfg DeviceConfig
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }

    err = ParseInterface(iniData, &cfg)
    if err != nil {
    t.Fatal(err)
    }
}

func TestWireguardConfWithManyAddress(t *testing.T) {
    const config = `
[Interface]
PrivateKey = mBsVDahr1XIu9PPd17UmsDdB6E53nvmS47NbNqQCiFM=
Address = 100.96.0.190,2606:B300:FFFF:fe8a:2ac6:c7e8:b021:6f5f/128
DNS = 198.18.0.1,198.18.0.2

[Peer]
PublicKey = SHnh4C2aDXhp1gjIqceGhJrhOLSeNYcqWLKcYnzj00U=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 192.200.144.22:51820`
    var cfg DeviceConfig
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }

    err = ParseInterface(iniData, &cfg)
    if err != nil {
    t.Fatal(err)
    }
}

// TestParseInterfaceInvalidPrivateKey verifies that an invalid base64 private key returns an error.
func TestParseInterfaceInvalidPrivateKey(t *testing.T) {
    const config = `
[Interface]
PrivateKey = invalidbase64==
Address = 10.5.0.2/24
DNS = 1.1.1.1`
    var cfg DeviceConfig
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    err = ParseInterface(iniData, &cfg)
    if err == nil {
    t.Fatal("expected error due to invalid private key")
    }
}

// TestParseInterfaceCheckAliveIntervalWithoutCheckAlive ensures that setting CheckAliveInterval without CheckAlive returns an error.
func TestParseInterfaceCheckAliveIntervalWithoutCheckAlive(t *testing.T) {
    const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/24
DNS = 1.1.1.1
CheckAliveInterval = 10`
    var cfg DeviceConfig
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    err = ParseInterface(iniData, &cfg)
    if err == nil {
    t.Fatal("expected an error because CheckAliveInterval was set without CheckAlive")
    }
}

// TestParseTCPClientTunnelConfig verifies the TCPClientTunnel configuration parsing.
func TestParseTCPClientTunnelConfig(t *testing.T) {
    const config = `
[TCPClientTunnel]
BindAddress = 127.0.0.1:1234
Target = example.com:80`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("TCPClientTunnel")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseTCPClientTunnelConfig(section)
    if err != nil {
    t.Fatal(err)
    }
    tcpConf, ok := conf.(*TCPClientTunnelConfig)
    if !ok {
    t.Fatal("expected TCPClientTunnelConfig")
    }
    if tcpConf.BindAddress.String() != "127.0.0.1:1234" {
    t.Errorf("expected bind address 127.0.0.1:1234, got %s", tcpConf.BindAddress.String())
    }
    if tcpConf.Target != "example.com:80" {
    t.Errorf("expected target example.com:80, got %s", tcpConf.Target)
    }
}

// TestParseSTDIOTunnelConfig verifies the STDIOTunnel configuration parsing.
func TestParseSTDIOTunnelConfig(t *testing.T) {
    const config = `
[STDIOTunnel]
Target = example.net`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("STDIOTunnel")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseSTDIOTunnelConfig(section)
    if err != nil {
    t.Fatal(err)
    }
    stdioConf, ok := conf.(*STDIOTunnelConfig)
    if !ok {
    t.Fatal("expected STDIOTunnelConfig")
    }
    if stdioConf.Target != "example.net" {
    t.Errorf("expected target example.net, got %s", stdioConf.Target)
    }
}

// TestParseTCPServerTunnelConfig verifies the TCPServerTunnel configuration parsing.
func TestParseTCPServerTunnelConfig(t *testing.T) {
    const config = `
[TCPServerTunnel]
ListenPort = 8080
Target = localhost:8080`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("TCPServerTunnel")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseTCPServerTunnelConfig(section)
    if err != nil {
    t.Fatal(err)
    }
    tcpServerConf, ok := conf.(*TCPServerTunnelConfig)
    if !ok {
    t.Fatal("expected TCPServerTunnelConfig")
    }
    if tcpServerConf.ListenPort != 8080 {
    t.Errorf("expected listen port 8080, got %d", tcpServerConf.ListenPort)
    }
    if tcpServerConf.Target != "localhost:8080" {
    t.Errorf("expected target localhost:8080, got %s", tcpServerConf.Target)
    }
}

// TestParseSocks5Config verifies the Socks5 configuration parsing.
func TestParseSocks5Config(t *testing.T) {
    const config = `
[Socks5]
BindAddress = 127.0.0.1:1080
Username = user
Password = pass`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Socks5")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseSocks5Config(section)
    if err != nil {
    t.Fatal(err)
    }
    socks5Conf, ok := conf.(*Socks5Config)
    if !ok {
    t.Fatal("expected Socks5Config")
    }
    if socks5Conf.BindAddress != "127.0.0.1:1080" {
    t.Errorf("expected bind address 127.0.0.1:1080, got %s", socks5Conf.BindAddress)
    }
    if socks5Conf.Username != "user" {
    t.Errorf("expected username user, got %s", socks5Conf.Username)
    }
    if socks5Conf.Password != "pass" {
    t.Errorf("expected password pass, got %s", socks5Conf.Password)
    }
}

// TestParseHTTPConfig verifies the HTTP configuration parsing.
func TestParseHTTPConfig(t *testing.T) {
    const config = `
[http]
BindAddress = 127.0.0.1:8080
Username = admin
Password = secret`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("http")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseHTTPConfig(section)
    if err != nil {
    t.Fatal(err)
    }
    httpConf, ok := conf.(*HTTPConfig)
    if !ok {
    t.Fatal("expected HTTPConfig")
    }
    if httpConf.BindAddress != "127.0.0.1:8080" {
    t.Errorf("expected bind address 127.0.0.1:8080, got %s", httpConf.BindAddress)
    }
    if httpConf.Username != "admin" {
    t.Errorf("expected username admin, got %s", httpConf.Username)
    }
    if httpConf.Password != "secret" {
    t.Errorf("expected password secret, got %s", httpConf.Password)
    }
}

// TestParseUDPProxyTunnelConfig verifies the UDPProxyTunnel configuration parsing.
func TestParseUDPProxyTunnelConfig(t *testing.T) {
    const config = `
[UDPProxyTunnel]
BindAddress = 0.0.0.0:8000
Target = example.org:8000
InactivityTimeout = 30`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("UDPProxyTunnel")
    if err != nil {
    t.Fatal(err)
    }
    conf, err := parseUDPProxyTunnelConfig(section)
    if err != nil {
    t.Fatal(err)
    }
    udpConf, ok := conf.(*UDPProxyTunnelConfig)
    if !ok {
    t.Fatal("expected UDPProxyTunnelConfig")
    }
    if udpConf.BindAddress != "0.0.0.0:8000" {
    t.Errorf("expected bind address 0.0.0.0:8000, got %s", udpConf.BindAddress)
    }
    if udpConf.Target != "example.org:8000" {
    t.Errorf("expected target example.org:8000, got %s", udpConf.Target)
    }
    if udpConf.InactivityTimeout != 30 {
    t.Errorf("expected inactivity timeout 30, got %d", udpConf.InactivityTimeout)
    }
}

// TestParseStringEnvSubstitution checks parsing a key that references an environment variable.
func TestParseStringEnvSubstitution(t *testing.T) {
    // Set the environment then defer unsetting it.
    os.Setenv("TESTVAR", "substituted")
    defer os.Unsetenv("TESTVAR")

    const config = `
[Section]
Key = $TESTVAR`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Section")
    if err != nil {
    t.Fatal(err)
    }
    value, err := parseString(section, "Key")
    if err != nil {
    t.Fatal(err)
    }
    if value != "substituted" {
    t.Errorf("expected value 'substituted', got %s", value)
    }
}

// TestParseStringDoubleDollar verifies that a key beginning with "$$" is converted correctly.
func TestParseStringDoubleDollar(t *testing.T) {
    const config = `
[Section]
Key = $$dollarvalue`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Section")
    if err != nil {
    t.Fatal(err)
    }
    value, err := parseString(section, "Key")
    if err != nil {
    t.Fatal(err)
    }
    if value != "$dollarvalue" {
    t.Errorf("expected value '$dollarvalue', got %s", value)
    }
}
// TestParseNetIPList tests parsing multiple IP addresses from a comma‐separated list.
func TestParseNetIPList(t *testing.T) {
    const config = `
[Section]
Key = 192.168.1.1, 10.0.0.1, , ::1`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Section")
    if err != nil {
    t.Fatal(err)
    }
    ips, err := parseNetIP(section, "Key")
    if err != nil {
    t.Fatal(err)
    }
    if len(ips) != 3 {
    t.Errorf("expected 3 IPs, got %d", len(ips))
    }
}

// TestParseCIDRNetIPList tests parsing IP addresses with optional CIDR mask.
func TestParseCIDRNetIPList(t *testing.T) {
    const config = `
[Section]
Key = 192.168.1.1/24, 10.0.0.1, ::1/128`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Section")
    if err != nil {
    t.Fatal(err)
    }
    addrs, err := parseCIDRNetIP(section, "Key")
    if err != nil {
    t.Fatal(err)
    }
    if len(addrs) != 3 {
    t.Errorf("expected 3 addresses, got %d", len(addrs))
    }
}

// TestParseAllowedIPsList tests parsing AllowedIPs into netip.Prefix slices.
func TestParseAllowedIPsList(t *testing.T) {
    const config = `
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0 , 192.168.1.0/24`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Peer")
    if err != nil {
    t.Fatal(err)
    }
    prefixes, err := parseAllowedIPs(section)
    if err != nil {
    t.Fatal(err)
    }
    if len(prefixes) != 3 {
    t.Errorf("expected 3 prefixes, got %d", len(prefixes))
    }
}

// TestEncodeBase64ToHexInvalidLength tests that a base64 string with incorrect length returns an error.
func TestEncodeBase64ToHexInvalidLength(t *testing.T) {
    // Create a base64 string that decodes to 8 bytes (instead of required 32 bytes)
    shortKey := "QUJDREVGR0g=" // decodes to "ABCDEFGH"
    _, err := encodeBase64ToHex(shortKey)
    if err == nil {
    t.Fatal("expected error due to key not being 32 bytes")
    }
}

// TestParseStringMissingEnv tests that referencing an unset environment variable returns an error.
func TestParseStringMissingEnv(t *testing.T) {
    const config = `
[Section]
Key = $UNSET_ENV_VAR`
    iniData, err := loadIniConfig(config)
    if err != nil {
    t.Fatal(err)
    }
    section, err := iniData.GetSection("Section")
    if err != nil {
    t.Fatal(err)
    }
    _, err = parseString(section, "Key")
    if err == nil {
    t.Fatal("expected error due to unset environment variable")
    }
}

// TestResolveIPPAndPortInvalid tests that resolveIPPAndPort returns error for an invalid address.
func TestResolveIPPAndPortInvalid(t *testing.T) {
    _, err := resolveIPPAndPort("invalidaddress")
    if err == nil {
    t.Fatal("expected error for invalid address")
    }
}

// TestParseRoutinesConfigNoSection tests that parsing a non-existent section does not error.
func TestParseRoutinesConfigNoSection(t *testing.T) {
    cfg, err := loadIniConfig("")
    if err != nil {
    t.Fatal(err)
    }
    var routines []RoutineSpawner
    err = parseRoutinesConfig(&routines, cfg, "NonExistentSection", parseSTDIOTunnelConfig)
    if err != nil {
    t.Fatal(err)
    }
    if len(routines) != 0 {
    t.Errorf("expected 0 routines, got %d", len(routines))
    }
}

// TestParseConfigWithWGConfig tests that the WGConfig key in the root is correctly used to load an alternate configuration.
func TestParseConfigWithWGConfig(t *testing.T) {
    // Create a temporary file with a valid WireGuard configuration.
    tmpFile, err := os.CreateTemp("", "wgconfig.ini")
    if err != nil {
    t.Fatal(err)
    }
    defer os.Remove(tmpFile.Name())
    wgConfigContent := `[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = 94.140.11.15:51820
AllowedIPs = 0.0.0.0/0, ::/0`
    _, err = tmpFile.WriteString(wgConfigContent)
    if err != nil {
    t.Fatal(err)
    }
    tmpFile.Close()

    // Create main config with WGConfig key pointing to the temp file.
    mainConfig := `WGConfig = ` + tmpFile.Name()

    // Write main config to a temporary file.
    mainTempFile, err := os.CreateTemp("", "mainconfig.ini")
    if err != nil {
    t.Fatal(err)
    }
    defer os.Remove(mainTempFile.Name())
    _, err = mainTempFile.WriteString(mainConfig)
    if err != nil {
    t.Fatal(err)
    }
    mainTempFile.Close()

    config, err := ParseConfig(mainTempFile.Name())
    if err != nil {
    t.Fatal(err)
    }
    if config.Device == nil {
    t.Fatal("expected DeviceConfig to be parsed")
    }
}