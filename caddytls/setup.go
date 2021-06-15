// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy"
	wstls "github.com/caddyserver/caddy/webscale/tls"
)

func init() {
	// opt-in TLS 1.3 for Go1.12
	// TODO: remove this line when Go1.13 is released.
	if err := os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1"); err != nil {
		log.Println("[ERROR] failed to set environment variable: ", err)
	}

	caddy.RegisterPlugin("tls", caddy.Plugin{Action: setupTLS})
}

// setupTLS sets up the TLS configuration and installs certificates that
// are specified by the user in the config file.
func setupTLS(c *caddy.Controller) error {
	configGetter, ok := configGetters[c.ServerType()]
	if !ok {
		return fmt.Errorf("no caddytls.ConfigGetter for %s server type; must call RegisterConfigGetter", c.ServerType())
	}
	config := configGetter(c)
	if config == nil {
		return fmt.Errorf("no caddytls.Config to set up for %s", c.Key)
	}

	config.Enabled = true

	for c.Next() {
		var certificateFile, keyFile, loadDir string

		args := c.RemainingArgs()
		if len(args) == 2 {
			certificateFile = args[0]
			keyFile = args[1]
			config.Manual = true
		}

		// Optional block with extra parameters
		var hadBlock bool
		for c.NextBlock() {
			hadBlock = true
			switch c.Val() {
			case "protocols":
				args := c.RemainingArgs()
				if len(args) == 1 {
					value, ok := SupportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					config.ProtocolMinVersion, config.ProtocolMaxVersion = value, value
				} else {
					value, ok := SupportedProtocols[strings.ToLower(args[0])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					config.ProtocolMinVersion = value
					value, ok = SupportedProtocols[strings.ToLower(args[1])]
					if !ok {
						return c.Errf("Wrong protocol name or protocol not supported: '%s'", args[1])
					}
					config.ProtocolMaxVersion = value
					if config.ProtocolMinVersion > config.ProtocolMaxVersion {
						return c.Errf("Minimum protocol version cannot be higher than maximum (reverse the order)")
					}
				}
			case "ciphers":
				for c.NextArg() {
					value, ok := SupportedCiphersMap[strings.ToUpper(c.Val())]
					if !ok {
						return c.Errf("Wrong cipher name or cipher not supported: '%s'", c.Val())
					}
					config.Ciphers = append(config.Ciphers, value)
				}
			case "curves":
				for c.NextArg() {
					value, ok := supportedCurvesMap[strings.ToUpper(c.Val())]
					if !ok {
						return c.Errf("Wrong curve name or curve not supported: '%s'", c.Val())
					}
					config.CurvePreferences = append(config.CurvePreferences, value)
				}
			case "clients":
				clientCertList := c.RemainingArgs()
				if len(clientCertList) == 0 {
					return c.ArgErr()
				}

				listStart, mustProvideCA := 1, true
				switch clientCertList[0] {
				case "request":
					config.ClientAuth = tls.RequestClientCert
					mustProvideCA = false
				case "require":
					config.ClientAuth = tls.RequireAnyClientCert
					mustProvideCA = false
				case "verify_if_given":
					config.ClientAuth = tls.VerifyClientCertIfGiven
				default:
					config.ClientAuth = tls.RequireAndVerifyClientCert
					listStart = 0
				}
				if mustProvideCA && len(clientCertList) <= listStart {
					return c.ArgErr()
				}

				config.ClientCerts = clientCertList[listStart:]
			case "insecure_disable_sni_matching":
				config.InsecureDisableSNIMatching = true
			case "load":
				c.Args(&loadDir)
				config.Manual = true
			case "alpn":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return c.ArgErr()
				}
				for _, arg := range args {
					config.ALPN = append(config.ALPN, arg)
				}
			default:
				return c.Errf("Unknown subdirective '%s'", c.Val())
			}
		}

		// tls requires at least one argument if a block is not opened
		if len(args) == 0 && !hadBlock {
			return c.ArgErr()
		}

		// load a single certificate and key, if specified
		if certificateFile != "" && keyFile != "" {
			err := config.Manager.CacheUnmanagedCertificatePEMFile(certificateFile, keyFile, nil)
			if err != nil {
				return c.Errf("Unable to load certificate and key files for '%s': %v", c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s and %s", certificateFile, keyFile)
		}

		// don't try to load certificates unless we're supposed to
		if !config.Enabled || !config.Manual {
			continue
		}

		// load a directory of certificates, if specified
		if loadDir != "" {
			err := loadCertsInDir(config, c, loadDir)
			if err != nil {
				return err
			}
		}
	}

	// If Webscale's 'strict_tls' plugin has created and set the cache override
	// in the Caddy instance, that must mean the Caddyfile includes
	// alias-certificate associations. As a result, use the override cache
	// instead of the default cache stored in config.Manager.
	if override := c.Get(wstls.OverrideCacheKey); override != nil {
		config.Manager.OverrideCache = override.(*wstls.AliasKeyedCache)
	}

	SetDefaultTLSParams(config)

	// store this as a custom config
	cfgMap, ok := c.Get(configMapKey).(map[string]*Config)
	if !ok || cfgMap == nil {
		cfgMap = make(map[string]*Config)
	}
	cfgMap[config.Hostname] = config
	c.Set(configMapKey, cfgMap)

	return nil
}

// loadCertsInDir loads all the certificates/keys in dir, as long as
// the file ends with .pem. This method of loading certificates is
// modeled after haproxy, which expects the certificate and key to
// be bundled into the same file:
// https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#5.1-crt
//
// This function may write to the log as it walks the directory tree.
func loadCertsInDir(cfg *Config, c *caddy.Controller, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("[WARNING] Unable to traverse into %s; skipping", path)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".pem") {
			certPEMBytes, keyPEMBytes, err := wstls.ParseCertificate(path)
			if err != nil {
				return c.Err(err.Error())
			}

			err = cfg.Manager.CacheUnmanagedCertificatePEMBytes(certPEMBytes, keyPEMBytes, nil)
			if err != nil {
				return c.Errf("%s: failed to load cert and key for '%s': %v", path, c.Key, err)
			}
			log.Printf("[INFO] Successfully loaded TLS assets from %s", path)
		}
		return nil
	})
}

const configMapKey = "tls_custom_configs"
