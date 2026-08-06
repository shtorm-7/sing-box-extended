package dion

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

func ZipEncode(value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(plain); err != nil {
		return "", fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("gzip close: %w", err)
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

func ZipDecode(encoded string, out any) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("base64: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer reader.Close()
	plain, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("gzip read: %w", err)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(plain, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}
