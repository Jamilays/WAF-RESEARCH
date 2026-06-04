// coraza-proxy — minimal Coraza-in-front-of-reverse-proxy for the WAF Lab.
//
// Reads CRS v4 from the coraza-coreruleset embedded FS, wraps a stdlib
// httputil.ReverseProxy with a custom middleware that mirrors
// corazahttp.WrapHandler's request-side processing and additionally
// stamps ``X-Coraza-Rules-Matched`` + ``X-Waflab-Waf: coraza`` onto
// every interrupted response. The engine's ``waf_headers`` capture
// surfaces both headers into each ``VerdictRecord`` so the dashboard /
// reporter can answer "which CRS rules fired on this block?".
//
// Response-phase rules (phase 3/4) are intentionally not wired —
// corazahttp.WrapHandler's ``rwInterceptor`` buffers response bodies
// for outbound inspection, which complicates header-stamping on phase
// 3/4 blocks. The lab's corpus is entirely request-side (SQLi / XSS /
// etc. in query/body), and CRS request-side rules cover the signal we
// care about; reinstating response-phase processing is an exercise for
// a future expansion.
//
// Paranoia level (and any other CRS tunables) are injected via the
// CORAZA_EXTRA_DIRECTIVES env var so the compose file can toggle
// defaults without rebuilding the image.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	backend := getenv("BACKEND", "http://whoami:80")
	listen := getenv("LISTEN_ADDR", ":80")
	extra := os.Getenv("CORAZA_EXTRA_DIRECTIVES")

	// SecRuleEngine defaults to DetectionOnly in @coraza.conf-recommended — at
	// that setting Coraza observes attacks but never 403s, which produced a
	// spurious 100% "bypass rate" in earlier runs. Force blocking mode for
	// parity with ModSecurity; override via CORAZA_BLOCKING_MODE=off if a
	// future profile wants monitor-only behaviour.
	blockingMode := getenv("CORAZA_BLOCKING_MODE", "on")
	engineDirective := "SecRuleEngine On"
	if blockingMode == "off" {
		engineDirective = "SecRuleEngine DetectionOnly"
	}

	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectivesFromFile("@owasp_crs/*.conf").
		WithDirectives(engineDirective)

	if extra != "" {
		cfg = cfg.WithDirectives(extra)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		log.Fatalf("coraza init: %v", err)
	}

	u, err := url.Parse(backend)
	if err != nil {
		log.Fatalf("invalid BACKEND %q: %v", backend, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = u.Host
	}

	// /healthz is served directly without routing through Coraza or the backend
	// target. Health must not depend on the application it protects — see
	// docs/DEV.md "Known gotchas".
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Waflab-Waf", "coraza")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/", wrapWAFWithRuleIDs(waf, proxy))

	log.Printf("coraza-proxy listening on %s, backend=%s, blocking_mode=%s, extra_directives=%dB",
		listen, backend, blockingMode, len(extra))
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatalf("http.ListenAndServe: %v", err)
	}
}

// wrapWAFWithRuleIDs replaces corazahttp.WrapHandler. Same request-phase
// processing, plus rule-ID capture on block. See the package-level comment
// for the response-phase trade-off.
func wrapWAFWithRuleIDs(waf coraza.WAF, upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		if tx.IsRuleEngineOff() {
			upstream.ServeHTTP(w, r)
			return
		}

		it, err := feedRequestToTx(tx, r)
		if err != nil {
			http.Error(w, "coraza request-processing error", http.StatusInternalServerError)
			return
		}

		if it != nil {
			writeInterrupt(w, tx, it)
			return
		}

		upstream.ServeHTTP(w, r)
	})
}

// feedRequestToTx mirrors corazahttp.processRequest (middleware.go) — the
// phase-0/1/2 feed. Kept close to upstream's implementation so behavioural
// parity with stock WrapHandler is easy to audit. The one divergence is
// that we don't call ProcessRequestBody when IsRequestBodyAccessible()
// returns false; upstream does call it for phase-2 SecRule coverage. We
// match upstream.
func feedRequestToTx(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	idx := strings.LastIndexByte(r.RemoteAddr, ':')
	if idx != -1 {
		client = r.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(r.RemoteAddr[idx+1:])
	}

	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vr := range r.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if it != nil {
			return it, nil
		}
		// Re-attach the body to the request so the upstream handler (reverse
		// proxy) can still forward it. ``tx.ReadRequestBodyFrom`` drained the
		// original ``r.Body``; if we don't re-init, the upstream sees an empty
		// body and the backend 500s / 502s. Matches upstream's approach in
		// corazahttp.processRequest — ``MultiReader(coraza-buffer, remaining)``
		// handles the case where coraza only buffered up to its limit.
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, fmt.Errorf("request body reader: %w", err)
		}
		r.Body = io.NopCloser(io.MultiReader(rbr, r.Body))
	}

	return tx.ProcessRequestBody()
}

// writeInterrupt emits the 4xx/5xx response with rule-ID fingerprint headers.
// The header scheme matches what the engine's waf_headers capture looks for
// (``x-coraza-*`` / ``x-waflab-*`` — see runner/engine.py _capture_waf_headers).
//
// ``X-Coraza-Rules-Matched`` carries the attack-detection rules only
// (CRS ID range [910000, 990000)). Setup / initialisation / anomaly-init
// rules (900xxx / 901xxx) match on every single request and drown out
// the actually-useful signal; callers that want the raw list can enable
// SecAuditLog instead.
func writeInterrupt(w http.ResponseWriter, tx types.Transaction, it *types.Interruption) {
	rules := tx.MatchedRules()
	ids := make([]string, 0, len(rules))
	seen := make(map[int]struct{}, len(rules))
	for _, mr := range rules {
		id := mr.Rule().ID()
		if !isAttackRule(id) {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, strconv.Itoa(id))
	}

	h := w.Header()
	h.Set("X-Waflab-Waf", "coraza")
	h.Set("X-Coraza-Action", it.Action)
	if len(ids) > 0 {
		h.Set("X-Coraza-Rules-Matched", strings.Join(ids, ","))
	}
	if it.RuleID != 0 {
		h.Set("X-Coraza-Interrupt-Rule", strconv.Itoa(it.RuleID))
	}

	status := http.StatusForbidden
	if it.Action == "deny" && it.Status != 0 {
		status = it.Status
	}
	w.WriteHeader(status)
}

// isAttackRule keeps CRS rules from the attack-detection bands and drops
// the setup / initialisation families that fire on every request.
//
// CRS v4 ID layout:
//
//	900xxx — initialisation, anti-evasion setup
//	901xxx — anomaly-score init, threshold configuration
//	910xxx — IP reputation / bad actor
//	913xxx — scanner detection
//	92xxxx — protocol enforcement / attack
//	93xxxx — application attack (LFI / RFI / RCE / PHP / generic)
//	94xxxx — application attack (XSS / SQLi / session-fix / Java)
//	949xxx — inbound anomaly threshold (the one that trips the 403)
//	95xxxx — outbound rules
//	98xxxx — correlation
func isAttackRule(id int) bool {
	return id >= 910000 && id < 990000
}
