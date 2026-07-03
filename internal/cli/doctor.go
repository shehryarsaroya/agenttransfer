package cli

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/server"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// Doctor runs self-host preflight checks against the current environment
// configuration and prints copy-paste fixes. Exit code 1 if anything failed.
func Doctor(out io.Writer) int {
	cfg, err := server.FromEnv()
	if err != nil {
		fmt.Fprintf(out, "✗ config: %v\n", err)
		return 1
	}

	failed := 0
	ok := func(format string, args ...any) { fmt.Fprintf(out, "  ✓ "+format+"\n", args...) }
	bad := func(format string, args ...any) { fmt.Fprintf(out, "  ✗ "+format+"\n", args...); failed++ }
	skip := func(format string, args ...any) { fmt.Fprintf(out, "  – "+format+"\n", args...) }
	fix := func(format string, args ...any) { fmt.Fprintf(out, "      fix: "+format+"\n", args...) }

	fmt.Fprintln(out, "agenttransfer doctor")

	// Data dir.
	fmt.Fprintln(out, "\nstorage:")
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		bad("DATA_DIR %s is not writable: %v", cfg.DataDir, err)
	} else if f, err := os.CreateTemp(cfg.DataDir, ".doctor-*"); err != nil {
		bad("DATA_DIR %s is not writable: %v", cfg.DataDir, err)
	} else {
		f.Close()
		os.Remove(f.Name())
		ok("DATA_DIR %s is writable", cfg.DataDir)
	}

	// Disk guard: the global backstop against filling the volume.
	if free, total, err := store.VolumeStats(cfg.DataDir); err != nil {
		skip("volume stats unavailable on this platform — the DISK_RESERVE guard is off")
	} else if reserve, rerr := server.ParseDiskReserve(cfg.DiskReserve, total); rerr != nil {
		bad("DISK_RESERVE %q: %v", cfg.DiskReserve, rerr)
	} else if reserve == 0 {
		skip("disk guard off (DISK_RESERVE=off) — %s free of %s", fmtBytes(free), fmtBytes(total))
	} else if free < reserve {
		bad("free space %s is below the %s reserve — uploads are being refused (HTTP 507)", fmtBytes(free), fmtBytes(reserve))
		fix("free disk space (delete agents/blobs, grow the volume) or lower DISK_RESERVE (currently %s)", cfg.DiskReserve)
	} else {
		ok("disk guard: %s free of %s (uploads refuse below %s)", fmtBytes(free), fmtBytes(total), fmtBytes(reserve))
	}

	if cfg.Domain == "" {
		fmt.Fprintln(out, "\nemail:")
		skip("DOMAIN is not set — local mode only (uploads, links, same-instance inbox all work)")
		skip("set DOMAIN=agents.example.com (plus DNS + OUTBOUND) to enable email")
		fmt.Fprintf(out, "\n%d problem(s) found\n", failed)
		if failed > 0 {
			return 1
		}
		return 0
	}

	// DNS.
	fmt.Fprintln(out, "\ndns:")
	ips, err := net.LookupHost(cfg.Domain)
	if err != nil || len(ips) == 0 {
		bad("A record: %s does not resolve", cfg.Domain)
		fix("add an A record for %s pointing at this server's public IP", cfg.Domain)
	} else {
		ok("A record: %s → %s", cfg.Domain, strings.Join(ips, ", "))
	}

	mxs, err := net.LookupMX(cfg.Domain)
	var mxHost string
	if err != nil || len(mxs) == 0 {
		bad("MX record: none found for %s", cfg.Domain)
		fix("add an MX record for %s pointing at %s (priority 10)", cfg.Domain, cfg.Domain)
	} else {
		mxHost = strings.TrimSuffix(mxs[0].Host, ".")
		ok("MX record: %s → %s", cfg.Domain, mxHost)
	}

	txts, _ := net.LookupTXT(cfg.Domain)
	hasSPF := false
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1") {
			hasSPF = true
			ok("SPF record: %q", t)
		}
	}
	if !hasSPF {
		bad("SPF record: no v=spf1 TXT on %s", cfg.Domain)
		fix(`add a TXT record per your relay's docs (Resend: "v=spf1 include:amazonses.com ~all" on the send subdomain it gives you)`)
	}

	// Inbound port 25.
	fmt.Fprintln(out, "\ninbound smtp:")
	if mxHost == "" {
		skip("skipping port-25 probe (no MX)")
	} else {
		conn, err := net.DialTimeout("tcp", mxHost+":25", 7*time.Second)
		if err != nil {
			bad("cannot reach %s:25 — %v", mxHost, err)
			fix("is `agenttransfer serve` running? does the host firewall / provider allow inbound port 25?")
			fix("note: this probe is from THIS machine; also test from elsewhere: nc -vz %s 25", mxHost)
		} else {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 128)
			n, _ := conn.Read(buf)
			conn.Close()
			greeting := strings.TrimSpace(string(buf[:n]))
			if strings.HasPrefix(greeting, "220") {
				ok("%s:25 answers: %s", mxHost, greeting)
			} else {
				bad("%s:25 connected but greeted oddly: %q", mxHost, greeting)
			}
		}
	}

	// TLS.
	fmt.Fprintln(out, "\ntls:")
	tconn, err := tls.DialWithDialer(&net.Dialer{Timeout: 7 * time.Second}, "tcp", cfg.Domain+":443", &tls.Config{ServerName: cfg.Domain})
	if err != nil {
		bad("no TLS on %s:443 — %v", cfg.Domain, err)
		fix("start `agenttransfer serve` with DOMAIN set; certmagic fetches a Let's Encrypt cert automatically (ports 80+443 must be open)")
	} else {
		cert := tconn.ConnectionState().PeerCertificates[0]
		tconn.Close()
		ok("certificate for %v valid until %s", cert.DNSNames, cert.NotAfter.Format("2006-01-02"))
	}

	// Outbound relay.
	fmt.Fprintln(out, "\noutbound relay:")
	if cfg.Outbound == "" {
		skip("OUTBOUND not set — agents can receive email but not send it")
		fix("get a free key at resend.com and set OUTBOUND=resend:re_...")
	} else if o, err := mail.ParseOutbound(cfg.Outbound); err != nil {
		bad("OUTBOUND unparseable: %v", err)
	} else if err := mail.TestAuth(o); err != nil {
		bad("relay authentication failed against %s: %v", o.Host, err)
		fix("check the key/credentials; Resend keys look like resend:re_...")
	} else {
		ok("relay authentication succeeded against %s", o.Host)
	}

	fmt.Fprintf(out, "\n%d problem(s) found\n", failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
