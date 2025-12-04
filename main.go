package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// NASClient represents a network access server (e.g., Mikrotik router)
type NASClient struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Secret string `json:"secret"`
}

// IPPool manages IP address assignment for VPN users
type IPPool struct {
	sync.Mutex
	StartIP   net.IP
	EndIP     net.IP
	Assigned  map[string]net.IP // username -> assigned IP
	Available []net.IP
}

// Config holds the server configuration
type Config struct {
	// RADIUS settings
	RadiusAddr    string
	ClientsFile   string
	DefaultSecret string

	// AD/LDAP settings
	LDAPServer   string
	LDAPPort     int
	LDAPBaseDN   string
	LDAPBindUser string
	LDAPBindPass string
	LDAPUseTLS   bool
	LDAPInsecure bool
	LDAPRetries  int

	// Optional: restrict to specific AD group
	RequiredGroup string

	// IP Pool for VPN
	IPPoolStart string
	IPPoolEnd   string

	// Logging
	JSONLogging bool
}

var (
	config    Config
	clients   map[string]NASClient // IP -> NASClient
	clientsMu sync.RWMutex
	ipPool    *IPPool
)

func main() {
	// Initialize logger (Windows Event Log or stdout)
	if err := InitLogger(); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer CloseLogger()

	// Parse command line flags
	flag.StringVar(&config.RadiusAddr, "radius-addr", ":1812", "RADIUS listen address")
	flag.StringVar(&config.ClientsFile, "clients-file", "", "JSON file with NAS clients (IP/secret pairs)")
	flag.StringVar(&config.DefaultSecret, "default-secret", "", "Default shared secret (if no clients file)")

	flag.StringVar(&config.LDAPServer, "ldap-server", "localhost", "AD/LDAP server hostname")
	flag.IntVar(&config.LDAPPort, "ldap-port", 389, "LDAP port (389 for LDAP/StartTLS, 636 for LDAPS)")
	flag.StringVar(&config.LDAPBaseDN, "ldap-base-dn", "", "LDAP base DN, e.g., dc=example,dc=com (required)")
	flag.StringVar(&config.LDAPBindUser, "ldap-bind-user", "", "LDAP bind user (optional, for user lookup)")
	flag.StringVar(&config.LDAPBindPass, "ldap-bind-pass", "", "LDAP bind password")
	flag.BoolVar(&config.LDAPUseTLS, "ldap-tls", false, "Use LDAPS (port 636) instead of StartTLS")
	flag.BoolVar(&config.LDAPInsecure, "ldap-insecure", true, "Skip TLS certificate verification")

	flag.StringVar(&config.RequiredGroup, "required-group", "Domain Users", "Require user to be member of this AD group (empty to disable)")

	flag.StringVar(&config.IPPoolStart, "ip-pool-start", "", "Start of IP pool for VPN users (e.g., 10.0.0.100)")
	flag.StringVar(&config.IPPoolEnd, "ip-pool-end", "", "End of IP pool for VPN users (e.g., 10.0.0.200)")

	flag.IntVar(&config.LDAPRetries, "ldap-retries", 3, "Number of LDAP connection retries")
	flag.BoolVar(&config.JSONLogging, "json", false, "Enable JSON structured logging")

	flag.Parse()

	// Enable JSON logging if requested
	SetJSONLogging(config.JSONLogging)

	// Validate required flags
	if config.ClientsFile == "" && config.DefaultSecret == "" {
		log.Fatal("Either --clients-file or --default-secret is required")
	}
	if config.LDAPBaseDN == "" {
		log.Fatal("--ldap-base-dn is required")
	}

	// Load NAS clients
	if err := loadClients(); err != nil {
		log.Fatalf("Failed to load clients: %v", err)
	}

	// Initialize IP pool if configured
	if config.IPPoolStart != "" && config.IPPoolEnd != "" {
		var err error
		ipPool, err = NewIPPool(config.IPPoolStart, config.IPPoolEnd)
		if err != nil {
			log.Fatalf("Failed to create IP pool: %v", err)
		}
		log.Printf("IP pool initialized: %s - %s (%d addresses)", config.IPPoolStart, config.IPPoolEnd, len(ipPool.Available))
	}

	// Create RADIUS server
	server := radius.PacketServer{
		Addr:         config.RadiusAddr,
		Handler:      radius.HandlerFunc(radiusHandler),
		SecretSource: &ClientSecretSource{},
	}

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		server.Shutdown(ctx)
	}()

	LogInfo(fmt.Sprintf("RADIUS server starting on %s", config.RadiusAddr))
	LogInfo(fmt.Sprintf("Authenticating against AD server: %s (domain: %s)", config.LDAPServer, baseDNToDomain(config.LDAPBaseDN)))
	if config.RequiredGroup != "" {
		LogInfo(fmt.Sprintf("Requiring group membership: %s", config.RequiredGroup))
	}
	LogInfo(fmt.Sprintf("Registered %d NAS client(s)", len(clients)))

	if err := server.ListenAndServe(); err != nil && err != radius.ErrServerShutdown {
		log.Fatalf("RADIUS server error: %v", err)
	}
}

// ClientSecretSource implements radius.SecretSource for per-client secrets
type ClientSecretSource struct{}

func (s *ClientSecretSource) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return nil, err
	}

	clientsMu.RLock()
	defer clientsMu.RUnlock()

	if client, ok := clients[host]; ok {
		return []byte(client.Secret), nil
	}

	// Fall back to default secret
	if config.DefaultSecret != "" {
		return []byte(config.DefaultSecret), nil
	}

	return nil, fmt.Errorf("unknown NAS client: %s", host)
}

func loadClients() error {
	clients = make(map[string]NASClient)

	if config.ClientsFile == "" {
		log.Println("No clients file specified, using default secret for all clients")
		return nil
	}

	data, err := os.ReadFile(config.ClientsFile)
	if err != nil {
		return fmt.Errorf("failed to read clients file: %w", err)
	}

	var clientList []NASClient
	if err := json.Unmarshal(data, &clientList); err != nil {
		return fmt.Errorf("failed to parse clients file: %w", err)
	}

	for _, c := range clientList {
		clients[c.IP] = c
		log.Printf("Registered NAS client: %s (%s)", c.Name, c.IP)
	}

	return nil
}

// NewIPPool creates a new IP address pool
func NewIPPool(startIP, endIP string) (*IPPool, error) {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP range: %s - %s", startIP, endIP)
	}

	pool := &IPPool{
		StartIP:   start,
		EndIP:     end,
		Assigned:  make(map[string]net.IP),
		Available: []net.IP{},
	}

	// Generate all IPs in range
	for ip := start; !ip.Equal(end); ip = nextIP(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		pool.Available = append(pool.Available, newIP)
	}
	// Include end IP
	endCopy := make(net.IP, len(end))
	copy(endCopy, end)
	pool.Available = append(pool.Available, endCopy)

	return pool, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

// GetIP assigns an IP to a user (or returns existing assignment)
func (p *IPPool) GetIP(username string) (net.IP, error) {
	p.Lock()
	defer p.Unlock()

	// Check if user already has an IP
	if ip, ok := p.Assigned[username]; ok {
		return ip, nil
	}

	// Assign new IP
	if len(p.Available) == 0 {
		return nil, fmt.Errorf("IP pool exhausted")
	}

	ip := p.Available[0]
	p.Available = p.Available[1:]
	p.Assigned[username] = ip

	return ip, nil
}

// ReleaseIP returns an IP to the pool
func (p *IPPool) ReleaseIP(username string) {
	p.Lock()
	defer p.Unlock()

	if ip, ok := p.Assigned[username]; ok {
		p.Available = append(p.Available, ip)
		delete(p.Assigned, username)
	}
}

func radiusHandler(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	// Get NAS info for logging
	nasIP := rfc2865.NASIPAddress_Get(r.Packet)
	nasID := rfc2865.NASIdentifier_GetString(r.Packet)
	nasIPStr := ""
	if nasIP != nil {
		nasIPStr = nasIP.String()
	}

	LogAuthRequest(username, nasIPStr, nasID)

	if username == "" || password == "" {
		LogAuthFailure(username, nasIPStr, "empty username or password")
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Authenticate against AD with retry
	if err := authenticateADWithRetry(username, password); err != nil {
		LogAuthFailure(username, nasIPStr, err.Error())
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	// Build response with attributes
	response := r.Response(radius.CodeAccessAccept)

	// Assign IP from pool if available
	assignedIP := ""
	if ipPool != nil {
		if ip, err := ipPool.GetIP(username); err == nil {
			// Framed-IP-Address (standard RADIUS attribute)
			rfc2865.FramedIPAddress_Set(response, ip)
			assignedIP = ip.String()
		} else {
			LogWarning(fmt.Sprintf("No IP available for user=%s: %v", username, err))
		}
	}

	LogAuthSuccess(username, nasIPStr, assignedIP)

	// Set Framed-Protocol to PPP (common for VPN)
	rfc2865.FramedProtocol_Set(response, rfc2865.FramedProtocol_Value_PPP)

	// Set Service-Type to Framed (for VPN/PPP)
	rfc2865.ServiceType_Set(response, rfc2865.ServiceType_Value_FramedUser)

	w.Write(response)
}

// authenticateADWithRetry wraps authenticateAD with retry logic
func authenticateADWithRetry(username, password string) error {
	var lastErr error
	for i := 0; i < config.LDAPRetries; i++ {
		err := authenticateAD(username, password)
		if err == nil {
			return nil
		}
		lastErr = err

		// Don't retry on auth failures (wrong password)
		if strings.Contains(err.Error(), "authentication failed") {
			return err
		}

		// Retry on connection errors with backoff
		if i < config.LDAPRetries-1 {
			backoff := time.Duration(100*(i+1)) * time.Millisecond
			LogWarning(fmt.Sprintf("LDAP connection failed, retrying in %v: %v", backoff, err))
			time.Sleep(backoff)
		}
	}
	return fmt.Errorf("LDAP failed after %d retries: %w", config.LDAPRetries, lastErr)
}

func authenticateAD(username, password string) error {
	// Connect to LDAP
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", config.LDAPServer, config.LDAPPort)

	tlsConfig := &tls.Config{
		ServerName:         config.LDAPServer,
		InsecureSkipVerify: config.LDAPInsecure,
	}

	if config.LDAPUseTLS {
		// LDAPS (port 636)
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Plain LDAP (no StartTLS for localhost)
		conn, err = ldap.Dial("tcp", address)
		if err == nil && config.LDAPPort == 389 && config.LDAPServer != "localhost" && config.LDAPServer != "127.0.0.1" {
			// Upgrade to TLS via StartTLS (skip for localhost)
			err = conn.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return fmt.Errorf("LDAP connect failed: %w", err)
	}
	defer conn.Close()

	// Build the user principal name (UPN) or DN for binding
	// AD typically accepts: user@domain.com or DOMAIN\user
	userPrincipal := username
	if !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
		// Extract domain from base DN and create UPN
		// dc=example,dc=com -> example.com
		domain := baseDNToDomain(config.LDAPBaseDN)
		userPrincipal = fmt.Sprintf("%s@%s", username, domain)
	}

	// Attempt to bind as the user (this validates the password)
	err = conn.Bind(userPrincipal, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// If a required group is specified, check membership
	if config.RequiredGroup != "" {
		if err := checkGroupMembership(conn, username); err != nil {
			return err
		}
	}

	return nil
}

func checkGroupMembership(conn *ldap.Conn, username string) error {
	// Search for the user to get their DN
	searchFilter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(username))

	searchRequest := ldap.NewSearchRequest(
		config.LDAPBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		searchFilter,
		[]string{"dn", "memberOf"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("user not found in directory")
	}

	// Check if user is member of required group
	memberOf := result.Entries[0].GetAttributeValues("memberOf")
	requiredGroupLower := strings.ToLower(config.RequiredGroup)

	for _, group := range memberOf {
		// Extract CN from the group DN
		groupLower := strings.ToLower(group)
		if strings.Contains(groupLower, "cn="+requiredGroupLower+",") ||
			strings.HasPrefix(groupLower, "cn="+requiredGroupLower+",") {
			return nil // User is in the required group
		}
	}

	return fmt.Errorf("user not member of required group: %s", config.RequiredGroup)
}

func baseDNToDomain(baseDN string) string {
	// Convert dc=example,dc=com to example.com
	var parts []string
	for _, part := range strings.Split(baseDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			parts = append(parts, part[3:])
		}
	}
	return strings.Join(parts, ".")
}
