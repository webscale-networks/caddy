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

// Package caddytls facilitates the management of TLS assets and integrates
// Let's Encrypt functionality into Caddy with first-class support for
// creating and renewing certificates automatically. It also implements
// the tls directive. It's mostly powered by the CertMagic package.
//
// This package is meant to be used by Caddy server types. To use the
// tls directive, a server type must import this package and call
// RegisterConfigGetter(). The server type must make and keep track of
// the caddytls.Config structs that this package produces. It must also
// add tls to its list of directives. When it comes time to make the
// server instances, the server type can call MakeTLSConfig() to convert
// a []caddytls.Config to a single tls.Config for use in tls.NewListener().
// It is also recommended to call RotateSessionTicketKeys() when
// starting a new listener.
package caddytls

// ConfigHolder is any type that has a Config; it presumably is
// connected to a hostname and port on which it is serving.
type ConfigHolder interface {
	TLSConfig() *Config
	Host() string
	Port() string
}
