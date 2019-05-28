package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

func fetchGcloudConfig(account string) (*gcloudConfig, error) {
	var buf bytes.Buffer
	args := []string{"config", "config-helper", "--format=json"}
	if account != "" {
		args = append(args, "--account="+account)
	}

	cmd := exec.Command("gcloud", args...)
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var parsed gcloudConfig
	err = json.Unmarshal(buf.Bytes(), &parsed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
