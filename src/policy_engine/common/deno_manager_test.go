package common

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDenoDownloadURL(t *testing.T) {
	tests := []struct {
		goos    string
		goarch  string
		wantErr bool
		wantURL string
	}{
		{"linux", "amd64", false, "https://github.com/denoland/deno/releases/download/v2.1.4/deno-x86_64-unknown-linux-gnu.zip"},
		{"linux", "arm64", false, "https://github.com/denoland/deno/releases/download/v2.1.4/deno-aarch64-unknown-linux-gnu.zip"},
		{"darwin", "amd64", false, "https://github.com/denoland/deno/releases/download/v2.1.4/deno-x86_64-apple-darwin.zip"},
		{"darwin", "arm64", false, "https://github.com/denoland/deno/releases/download/v2.1.4/deno-aarch64-apple-darwin.zip"},
		{"windows", "amd64", false, "https://github.com/denoland/deno/releases/download/v2.1.4/deno-x86_64-pc-windows-msvc.zip"},
		{"freebsd", "amd64", true, ""},
		{"linux", "386", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.goos+"/"+tt.goarch, func(t *testing.T) {
			url, err := DenoDownloadURL(DenoVersion, tt.goos, tt.goarch)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %s/%s", tt.goos, tt.goarch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if url != tt.wantURL {
				t.Errorf("expected URL %s, got %s", tt.wantURL, url)
			}
		})
	}
}

func TestGetEmbeddedDenoZip(t *testing.T) {
	// Without embed_deno build tag, this should return nil
	data := GetEmbeddedDenoZip()
	if data != nil {
		t.Log("Deno is embedded (built with embed_deno tag)")
	} else {
		t.Log("Deno is not embedded (default build)")
	}
}

func TestDefaultCacheDir(t *testing.T) {
	dir := defaultCacheDir()
	if dir == "" {
		t.Error("expected non-empty cache dir")
	}
	t.Logf("Default cache dir: %s", dir)
}

func TestExtractDenoFromZipInvalid(t *testing.T) {
	err := extractDenoFromZip([]byte("not a zip"), t.TempDir())
	if err == nil {
		t.Error("expected error for invalid zip data")
	}
}

func TestTryExtractEmbeddedDenoNoEmbed(t *testing.T) {
	// Without embed_deno build tag, should return empty
	path := tryExtractEmbeddedDeno(t.TempDir())
	if GetEmbeddedDenoZip() == nil && path != "" {
		t.Errorf("expected empty path when no embedded deno, got %s", path)
	}
}

func TestResolveDeno(t *testing.T) {
	// Reset cache so we get a fresh resolution
	ResetDenoCache()

	cacheDir := t.TempDir()
	path := ResolveDeno(cacheDir)

	// On CI/test machines deno might not be available and download might
	// be blocked, so we just check the function doesn't panic.
	t.Logf("Resolved deno path: %q", path)

	// If deno was found, verify it exists
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("resolved deno path doesn't exist: %s", path)
		}
	}

	// Reset for other tests
	ResetDenoCache()
}

func TestTransformPropertyAccessors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"SimpleProperty",
			"github.actor",
			"github['actor']",
		},
		{
			"NestedProperty",
			"steps.step1.outputs.result",
			"steps['step1']['outputs']['result']",
		},
		{
			"PreserveStrings",
			`"github.actor"`,
			`"github.actor"`,
		},
		{
			"MixedExpression",
			`github.actor_id + " " + 'https://github.com' + '/' + github.actor`,
			`github['actor_id'] + " " + 'https://github.com' + '/' + github['actor']`,
		},
		{
			"NoProperties",
			`"hello world"`,
			`"hello world"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformPropertyAccessors(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDownloadDenoCachesResult(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping download test in short mode")
	}

	cacheDir := t.TempDir()

	// Check the correct binary name for this platform
	binaryName := "deno"
	if runtime.GOOS == "windows" {
		binaryName = "deno.exe"
	}
	expectedDir := filepath.Join(cacheDir, "deno-"+DenoVersion+"-"+runtime.GOOS+"-"+runtime.GOARCH)
	expectedPath := filepath.Join(expectedDir, binaryName)

	// First call downloads
	path, err := downloadDeno(cacheDir, DenoVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skipf("download failed (may be offline): %v", err)
	}

	if path != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, path)
	}

	// Second call should use cached version
	path2, err := downloadDeno(cacheDir, DenoVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if path2 != path {
		t.Errorf("expected cached path %s, got %s", path, path2)
	}
}
