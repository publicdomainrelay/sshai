//go:build embed_deno && darwin && arm64

package common

import _ "embed"

//go:embed deno_embedded/deno-darwin-arm64.zip
var embeddedDenoZip []byte

func GetEmbeddedDenoZip() []byte { return embeddedDenoZip }
