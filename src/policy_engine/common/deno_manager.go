package common

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	// DenoVersion is the version of Deno to download if not embedded or found in PATH.
	DenoVersion = "v2.1.4"
)

var (
	// denoOnce ensures we only resolve the deno path once.
	denoOnce sync.Once
	// denoCachedPath is the resolved deno binary path.
	denoCachedPath string
)

// DenoDownloadURL returns the download URL for Deno for the given OS/arch.
func DenoDownloadURL(version, goos, goarch string) (string, error) {
	var target string
	switch {
	case goos == "linux" && goarch == "amd64":
		target = "deno-x86_64-unknown-linux-gnu.zip"
	case goos == "linux" && goarch == "arm64":
		target = "deno-aarch64-unknown-linux-gnu.zip"
	case goos == "darwin" && goarch == "amd64":
		target = "deno-x86_64-apple-darwin.zip"
	case goos == "darwin" && goarch == "arm64":
		target = "deno-aarch64-apple-darwin.zip"
	case goos == "windows" && goarch == "amd64":
		target = "deno-x86_64-pc-windows-msvc.zip"
	default:
		return "", fmt.Errorf("unsupported platform: %s/%s", goos, goarch)
	}
	return fmt.Sprintf("https://github.com/denoland/deno/releases/download/%s/%s", version, target), nil
}

// ResolveDeno finds or provisions a Deno binary. Resolution order:
//  1. Embedded binary (if built with -tags embed_deno)
//  2. System PATH
//  3. Download to cache directory
//
// The result is cached for subsequent calls.
func ResolveDeno(cacheDir string) string {
	denoOnce.Do(func() {
		denoCachedPath = resolveDeno(cacheDir)
	})
	return denoCachedPath
}

// ResetDenoCache clears the cached deno path (useful for testing).
func ResetDenoCache() {
	denoOnce = sync.Once{}
	denoCachedPath = ""
}

func resolveDeno(cacheDir string) string {
	// 1. Try extracting embedded Deno
	if path := tryExtractEmbeddedDeno(cacheDir); path != "" {
		log.Printf("Using embedded Deno: %s", path)
		return path
	}

	// 2. Try system PATH
	if path, err := exec.LookPath("deno"); err == nil {
		log.Printf("Using system Deno: %s", path)
		return path
	}

	// 3. Download on demand
	path, err := downloadDeno(cacheDir, DenoVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Printf("Warning: failed to provision Deno: %v", err)
		return ""
	}
	log.Printf("Downloaded Deno to: %s", path)
	return path
}

// tryExtractEmbeddedDeno extracts the embedded Deno zip (if available) to the
// cache directory and returns the path to the binary. Returns "" if no
// embedded binary is available.
func tryExtractEmbeddedDeno(cacheDir string) string {
	data := GetEmbeddedDenoZip()
	if data == nil {
		return ""
	}

	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}

	denoDir := filepath.Join(cacheDir, "deno-embedded")
	binaryName := "deno"
	if runtime.GOOS == "windows" {
		binaryName = "deno.exe"
	}
	denoPath := filepath.Join(denoDir, binaryName)

	// Check if already extracted
	if info, err := os.Stat(denoPath); err == nil && !info.IsDir() {
		return denoPath
	}

	// Extract from zip
	if err := os.MkdirAll(denoDir, 0755); err != nil {
		log.Printf("Warning: failed to create deno cache dir: %v", err)
		return ""
	}

	if err := extractDenoFromZip(data, denoDir); err != nil {
		log.Printf("Warning: failed to extract embedded deno: %v", err)
		return ""
	}

	// Ensure executable
	os.Chmod(denoPath, 0755)

	if _, err := os.Stat(denoPath); err == nil {
		return denoPath
	}
	return ""
}

// downloadDeno downloads Deno to the cache directory and returns the binary path.
func downloadDeno(cacheDir, version, goos, goarch string) (string, error) {
	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}

	denoDir := filepath.Join(cacheDir, fmt.Sprintf("deno-%s-%s-%s", version, goos, goarch))
	binaryName := "deno"
	if goos == "windows" {
		binaryName = "deno.exe"
	}
	denoPath := filepath.Join(denoDir, binaryName)

	// Check if already downloaded
	if info, err := os.Stat(denoPath); err == nil && !info.IsDir() {
		return denoPath, nil
	}

	// Get download URL
	downloadURL, err := DenoDownloadURL(version, goos, goarch)
	if err != nil {
		return "", err
	}

	log.Printf("Downloading Deno %s for %s/%s from %s", version, goos, goarch, downloadURL)

	// Download
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download deno: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read download: %w", err)
	}

	// Extract
	if err := os.MkdirAll(denoDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create deno dir: %w", err)
	}

	if err := extractDenoFromZip(zipData, denoDir); err != nil {
		return "", fmt.Errorf("failed to extract deno: %w", err)
	}

	os.Chmod(denoPath, 0755)

	if _, err := os.Stat(denoPath); err != nil {
		return "", fmt.Errorf("deno binary not found after extraction: %w", err)
	}

	return denoPath, nil
}

// extractDenoFromZip extracts a Deno zip archive into destDir.
func extractDenoFromZip(zipData []byte, destDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}

	for _, f := range reader.File {
		// Only extract the deno binary (skip directories, other files)
		name := filepath.Base(f.Name)
		if !strings.HasPrefix(name, "deno") {
			continue
		}

		destPath := filepath.Join(destDir, name)

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open zip entry %s: %w", f.Name, err)
		}

		outFile, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create %s: %w", destPath, err)
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return fmt.Errorf("failed to extract %s: %w", f.Name, err)
		}

		outFile.Close()
		rc.Close()
		os.Chmod(destPath, 0755)
	}

	return nil
}

// defaultCacheDir returns a default cache directory for Deno.
func defaultCacheDir() string {
	// Use XDG cache or home dir
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "policy_engine")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "policy_engine_cache")
	}
	return filepath.Join(home, ".cache", "policy_engine")
}
