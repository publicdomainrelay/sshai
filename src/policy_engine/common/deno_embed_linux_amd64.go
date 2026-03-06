//go:build embed_deno && linux && amd64

package common

import _ "embed"

//go:embed deno_embedded/deno-linux-amd64.zip
var embeddedDenoZip []byte

func GetEmbeddedDenoZip() []byte { return embeddedDenoZip }
