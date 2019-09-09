// Copyright 2015 Matthew Holt and The Caddy Authors
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

package caddycmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func gracefullyStopProcess(pid int) error {
	fmt.Printf("Forceful Stop...")
	// process on windows will not stop unless forced with /f
	cmd := exec.Command("taskkill", "/pid", strconv.Itoa(pid), "/f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("taskkill: %v", err)
	}
	return nil
}

// On Windows the app name passed in os.Args[0] will match how
// caddy was started eg will match caddy or caddy.exe.
// So return appname with .exe for consistency
func getProcessName() string {
	base := filepath.Base(os.Args[0])
	if filepath.Ext(base) == "" {
		return base + ".exe"
	}
	return base
}