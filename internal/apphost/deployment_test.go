package apphost

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackagedRunnerStateDirectoryMatchesSandboxPath(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate deployment test source")
	}
	unitPath := filepath.Join(filepath.Dir(source), "..", "..", "deploy", "agenttransfer-app-runner.service")
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, required := range []string{
		"Environment=APP_DATA_ROOT=/var/lib/agenttransfer-app-data",
		"Environment=APP_SNAPSHOT_ROOT=/var/lib/agenttransfer-app-snapshots",
		"StateDirectory=agenttransfer-app-data agenttransfer-app-snapshots",
		"ReadWritePaths=/var/lib/agenttransfer-app-data ",
		"/var/lib/agenttransfer-app-snapshots ",
		"ReadOnlyPaths=-/var/lib/private/agenttransfer/app-builds",
		"was not created within 30s",
		"PartOf=agenttransfer.service",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("runner unit is missing matching state path %q", required)
		}
	}
	if strings.Contains(unit, "/var/lib/private/agenttransfer-app-data") ||
		strings.Contains(unit, "APP_SNAPSHOT_ROOT=/run/") {
		t.Fatal("runner unit uses an incorrect private-state path or tmpfs-backed snapshot default")
	}
}

func TestPackagedBackupRestartsSharedBinaryProcesses(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate deployment test source")
	}
	unitPath := filepath.Join(filepath.Dir(source), "..", "..", "deploy", "agenttransfer-backup.service")
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, required := range []string{
		"systemctl is-active --quiet agenttransfer-app-runner && runner_restart_needed=1",
		"systemctl stop agenttransfer-app-runner",
		"systemctl start agenttransfer-app-runner",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("backup unit is missing runner lifecycle step %q", required)
		}
	}
}
