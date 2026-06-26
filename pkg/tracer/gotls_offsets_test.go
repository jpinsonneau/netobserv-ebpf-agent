package tracer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResolveGoTLSOffsetsOnBuiltBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skips compiling test binary in short mode")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "main.go")
	bin := filepath.Join(tmp, "httpserver")
	if err := os.WriteFile(src, []byte(`package main
import (
	"crypto/tls"
	"net/http"
)
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	_ = tls.VersionTLS13
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	offsets, err := ResolveGoTLSOffsets(bin)
	if err != nil {
		t.Fatalf("ResolveGoTLSOffsets: %v", err)
	}
	if offsets.WriteOffset == 0 {
		t.Fatal("expected write offset")
	}
	if offsets.ReadEntry == 0 {
		t.Fatal("expected read entry offset")
	}
	if len(offsets.ReadReturns) == 0 {
		t.Fatal("expected read RET offsets")
	}
	if !offsets.RegisterABI {
		t.Fatalf("expected register ABI for current Go toolchain")
	}
}

func TestRetOffsetsInCode(t *testing.T) {
	code := []byte{0x90, 0xc3, 0x90, 0xc2, 0x00, 0x00}
	got, err := retOffsetsInCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("unexpected offsets: %v", got)
	}
}
