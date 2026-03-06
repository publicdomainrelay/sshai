//go:build !embed_deno

package common

// GetEmbeddedDenoZip returns nil when Deno is not embedded.
// The deno_manager will fall back to finding Deno in PATH or downloading it.
func GetEmbeddedDenoZip() []byte {
	return nil
}
