//go:build tools

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package main

import (
	_ "github.com/google/go-licenses"
	_ "github.com/katexochen/sh/v3/cmd/shfmt"
	_ "golang.org/x/tools/cmd/stringer"
	_ "golang.org/x/vuln/cmd/govulncheck"
)
