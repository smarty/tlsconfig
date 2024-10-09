package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func New(options ...option) (*tls.Config, error) {
	var config configuration
	Options.apply(options...)(&config)

	if !config.Enabled {
		return nil, nil
	}

	target := config.Base.Clone()

	if target.RootCAs == nil {
		target.RootCAs = x509.NewCertPool()
	}
	if config.TrustSystemRootCAs {
		if trusted, err := x509.SystemCertPool(); err != nil {
			return nil, err
		} else {
			target.RootCAs = trusted
		}
	}

	if trustedCAs, err := resolvePEM(config.TrustedCAsPEM, config.TrustedCAsPEMFile); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrReadPEMFile, err)
	} else if trustedCAs == nil {
		// no-op
	} else if ok := target.RootCAs.AppendCertsFromPEM(trustedCAs); !ok {
		return nil, fmt.Errorf("unable to parse trusted CA PEM: %w", ErrMalformedPEM)
	}

	for len(config.X509KeyPairs) > 0 {
		var (
			certPEMBlock = []byte(config.X509KeyPairs[0])
			keyPEMBlock  = []byte(config.X509KeyPairs[1])
		)
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return nil, fmt.Errorf("unable to parse x509 keypair from PEM: %w", err)
		}
		target.Certificates = append(target.Certificates, cert)
		config.X509KeyPairs = config.X509KeyPairs[2:]
	}

	if len(config.ServerName) > 0 {
		target.ServerName = config.ServerName
	}

	target.MinVersion = config.MinTLSVersion
	target.MaxVersion = config.MaxTLSVersion

	// FUTURE: support server certificate(s), and password-protected RSA/EC private key
	return target, nil
}
func resolvePEM(source, filename string) ([]byte, error) {
	if len(filename) > 0 {
		if raw, err := os.ReadFile(filename); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrReadPEMFile, err)
		} else {
			return raw, nil
		}
	}

	if len(source) == 0 {
		return nil, nil
	}

	if resolved := tryReadValue(source); len(resolved) > 0 {
		return []byte(resolved), nil
	}

	return nil, ErrReadPEMFile
}
func tryReadValue(value string) string {
	if len(value) == 0 {
		return ""
	} else if parsed := parseURL(value); parsed != nil && parsed.Scheme == "env" {
		return os.Getenv(parsed.Host)
	} else if parsed != nil && parsed.Scheme == "file" {
		raw, _ := os.ReadFile(parsed.Path)
		value = strings.TrimSpace(string(raw))
		return value
	} else {
		return value
	}
}
func parseURL(value string) *url.URL {
	value = strings.TrimSpace(value)
	if len(value) == 0 {
		return nil
	} else if parsed, err := url.Parse(value); err != nil {
		return nil
	} else {
		return parsed
	}
}

type configuration struct {
	Enabled            bool
	Base               *tls.Config
	TrustSystemRootCAs bool
	ServerName         string
	TrustedCAsPEM      string
	TrustedCAsPEMFile  string
	X509KeyPairs       []string
	MinTLSVersion      uint16
	MaxTLSVersion      uint16
}

func (singleton) Enabled(value bool) option {
	return func(this *configuration) { this.Enabled = value }
}
func (singleton) Base(value *tls.Config) option {
	return func(this *configuration) { this.Base = value }
}
func (singleton) TrustSystemRootCAs(value bool) option {
	return func(this *configuration) { this.TrustSystemRootCAs = value }
}
func (singleton) ServerName(value string) option {
	return func(this *configuration) { this.ServerName = value }
}
func (singleton) TrustedCAsPEM(value string) option {
	return func(this *configuration) { this.TrustedCAsPEM = value }
}
func (singleton) TrustedCAsPEMFile(value string) option {
	return func(this *configuration) {
		switch value {
		case "public-ca", "true":
			this.TrustedCAsPEMFile = ""
			this.TrustSystemRootCAs = true
		default:
			this.TrustedCAsPEMFile = value
		}
	}
}
func (singleton) X509KeyPair(certPEMBlock, keyPEMBlock string) option {
	return func(this *configuration) { this.X509KeyPairs = append(this.X509KeyPairs, certPEMBlock, keyPEMBlock) }
}
func (singleton) MinTLSVersion(value uint16) option {
	return func(this *configuration) { this.MinTLSVersion = value }
}
func (singleton) MaxTLSVersion(value uint16) option {
	return func(this *configuration) { this.MaxTLSVersion = value }
}
func (singleton) apply(options ...option) option {
	return func(this *configuration) {
		for _, item := range Options.defaults(options...) {
			item(this)
		}
	}
}
func (singleton) defaults(options ...option) []option {
	return append([]option{
		Options.Enabled(true),
		Options.Base(&tls.Config{}),
		Options.TrustSystemRootCAs(true),
		Options.ServerName(""),
		Options.TrustedCAsPEM(""),
		Options.TrustedCAsPEMFile(""),
		Options.MinTLSVersion(tls.VersionTLS12),
		Options.MaxTLSVersion(tls.VersionTLS13),
	}, options...)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type option func(*configuration)
type singleton struct{}

var Options singleton
