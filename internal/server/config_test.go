package server

import "testing"

func TestParseSizeRejectsNonFiniteAndOverflow(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-Inf", "100000000000000000000", "9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseSize(value); err == nil {
				t.Fatalf("ParseSize accepted %q", value)
			}
		})
	}
	if got, err := ParseSize("1.5GB"); err != nil || got != int64(1.5*float64(1<<30)) {
		t.Fatalf("ParseSize(1.5GB) = %d, %v", got, err)
	}
}

func TestConfigRejectsPlaintextDomainListener(t *testing.T) {
	bad := Config{Domain: "agents.example.com", HTTPAddr: ":8443"}
	bad.ApplyDefaults()
	if err := bad.Validate(); err == nil {
		t.Fatal("DOMAIN with a non-TLS listen port was accepted")
	}

	good := Config{Domain: "agents.example.com", HTTPAddr: "0.0.0.0:443"}
	good.ApplyDefaults()
	if err := good.Validate(); err != nil {
		t.Fatalf("explicit port 443 was rejected: %v", err)
	}
	if !good.builtInTLS() {
		t.Fatal("port 443 address did not enable built-in TLS")
	}
}

func TestParsersRejectNonFinitePercentAndDuration(t *testing.T) {
	for _, value := range []string{"NaN%", "+Inf%", "-Inf%"} {
		if _, err := ParseDiskReserve(value, 1<<30); err == nil {
			t.Fatalf("ParseDiskReserve accepted %q", value)
		}
	}
	for _, value := range []string{"NaNd", "+Infd", "-Infd"} {
		if _, err := ParseTTL(value); err == nil {
			t.Fatalf("ParseTTL accepted %q", value)
		}
	}
}

func TestConfigValidatesAdvertisedAndConnectOrigins(t *testing.T) {
	validPublic := []string{"https://agents.example.com", "https://agents.example.com:8443", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"}
	for _, raw := range validPublic {
		cfg := Config{PublicURL: raw}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("PUBLIC_URL %q rejected: %v", raw, err)
		}
	}
	invalidPublic := []string{"http://agents.example.com", "https://user@agents.example.com", "https://agents.example.com/base", "https://agents.example.com?x=1", "//agents.example.com", "https://"}
	for _, raw := range invalidPublic {
		cfg := Config{PublicURL: raw}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Errorf("PUBLIC_URL %q accepted", raw)
		}
	}

	validConnect := []string{"https://connect.example.com", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"}
	for _, raw := range validConnect {
		cfg := Config{Connect: raw}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("CONNECT %q rejected: %v", raw, err)
		}
	}
	invalidConnect := []string{"http://connect.example.com", "https://user@connect.example.com", "https://connect.example.com/base", "https://connect.example.com?x=1"}
	for _, raw := range invalidConnect {
		cfg := Config{Connect: raw}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Errorf("CONNECT %q accepted", raw)
		}
	}
}

func TestPublicURLUnderHostRequiresCleanHTTPSSubdomain(t *testing.T) {
	for _, raw := range []string{"https://child.connect.example.com/path", "https://user@child.connect.example.com", "https://connect.example.com", "http://child.connect.example.com", "https://child.connect.example.com:8443"} {
		if publicURLUnderHost(raw, "https://connect.example.com") {
			t.Errorf("unsafe public URL %q accepted", raw)
		}
	}
	if !publicURLUnderHost("https://child.connect.example.com", "https://connect.example.com") {
		t.Fatal("valid connect subdomain rejected")
	}
}

func TestConnectDomainRequiresDNSLabelBoundary(t *testing.T) {
	for _, connectDomain := range []string{"example.com", "connect.example.com", "deep.connect.example.com", "CONNECT.EXAMPLE.COM"} {
		cfg := Config{Domain: "example.com", ConnectDomain: connectDomain}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("CONNECT_DOMAIN %q rejected: %v", connectDomain, err)
		}
	}
	if !sameOrSubdomain("CONNECT.EXAMPLE.COM.", "Example.Com") {
		t.Fatal("case-insensitive DNS subdomain was rejected")
	}
	for _, connectDomain := range []string{"evil-example.com", "example.com.evil", "notexample.com"} {
		cfg := Config{Domain: "example.com", ConnectDomain: connectDomain}
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Errorf("CONNECT_DOMAIN %q accepted outside example.com", connectDomain)
		}
	}
}
