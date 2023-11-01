package main

import "embed"

//go:embed *.html
//go:embed *.md
//go:embed static
//go:embed fun
var content embed.FS
