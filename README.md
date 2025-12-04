# RADIUS-AD Server

A lightweight, extensible RADIUS server in Go that authenticates against Active Directory.

## Features

- RADIUS authentication (RFC 2865)
- Active Directory / LDAP authentication
- Optional AD group membership requirement
- TLS/StartTLS support
- Single binary, no dependencies
- Cross-platform (Windows, Linux, macOS)

## Building

### Build for current platform

```bash
go mod tidy
go build -o radius-ad .
```

### Build Windows .exe (from Linux/macOS)

```bash
GOOS=windows GOARCH=amd64 go build -o radius-ad.exe .
```

### Build with version info (Windows)

```bash
# Install goversioninfo for Windows resource embedding
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest

# Build with embedded version info
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o radius-ad.exe .
```

## Usage

```bash
# Basic usage
./radius-ad \
  --radius-secret "your-shared-secret" \
  --ldap-server "dc01.example.com" \
  --ldap-base-dn "dc=example,dc=com"

# With group requirement
./radius-ad \
  --radius-secret "your-shared-secret" \
  --ldap-server "dc01.example.com" \
  --ldap-base-dn "dc=example,dc=com" \
  --required-group "VPN-Users"

# Using LDAPS (port 636)
./radius-ad \
  --radius-secret "your-shared-secret" \
  --ldap-server "dc01.example.com" \
  --ldap-port 636 \
  --ldap-tls \
  --ldap-base-dn "dc=example,dc=com"
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--radius-addr` | `:1812` | RADIUS listen address |
| `--radius-secret` | (required) | RADIUS shared secret |
| `--ldap-server` | (required) | AD/LDAP server hostname |
| `--ldap-port` | `389` | LDAP port |
| `--ldap-base-dn` | (required) | LDAP base DN |
| `--ldap-bind-user` | | Service account for lookups |
| `--ldap-bind-pass` | | Service account password |
| `--ldap-tls` | `false` | Use LDAPS instead of StartTLS |
| `--ldap-insecure` | `false` | Skip TLS cert verification |
| `--required-group` | | Require AD group membership |

## Running as Windows Service

Use [NSSM](https://nssm.cc/) to install as a Windows service:

```powershell
# Download NSSM and install the service
nssm install RadiusAD "C:\path\to\radius-ad.exe"
nssm set RadiusAD AppParameters "--radius-secret secret --ldap-server dc01.example.com --ldap-base-dn dc=example,dc=com"
nssm set RadiusAD Description "RADIUS server with AD authentication"
nssm start RadiusAD
```

Or use the built-in Windows Service wrapper (see `service_windows.go`).

## Testing

Use `radtest` (from FreeRADIUS) to test:

```bash
radtest username password localhost 0 your-shared-secret
```

Or use NTRadPing on Windows.

## Extending

### Add custom attributes to Accept response

```go
func radiusHandler(w radius.ResponseWriter, r *radius.Request) {
    // ... authentication code ...

    response := r.Response(radius.CodeAccessAccept)

    // Add VLAN assignment
    rfc2868.TunnelType_Set(response, rfc2868.TunnelType_Value_VLAN)
    rfc2868.TunnelMediumType_Set(response, rfc2868.TunnelMediumType_Value_IEEE802)
    rfc2868.TunnelPrivateGroupID_SetString(response, "100")

    w.Write(response)
}
```

### Add vendor-specific attributes

```go
import "layeh.com/radius/vendors/microsoft"

// In your handler:
microsoft.MSMPPERecvKey_Set(response, recvKey)
microsoft.MSMPPESendKey_Set(response, sendKey)
```

## License

MIT
