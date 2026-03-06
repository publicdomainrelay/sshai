//go:build embed_deno && darwin && amd64

package common

import _ "embed"

//go:embed deno_embedded/deno-darwin-amd64.zip
var embeddedDenoZip []byte

func GetEmbeddedDenoZip() []byte { return embeddedDenoZip }
