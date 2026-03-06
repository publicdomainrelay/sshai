//go:build embed_deno && windows && amd64

package common

import _ "embed"

//go:embed deno_embedded/deno-windows-amd64.zip
var embeddedDenoZip []byte

func GetEmbeddedDenoZip() []byte { return embeddedDenoZip }
