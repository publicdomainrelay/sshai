//go:build embed_deno && linux && arm64

package common

import _ "embed"

//go:embed deno_embedded/deno-linux-arm64.zip
var embeddedDenoZip []byte

func GetEmbeddedDenoZip() []byte { return embeddedDenoZip }
