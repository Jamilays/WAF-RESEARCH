package main

import "testing"

// TestIsAttackRule locks the CRS ID-range filter that writeInterrupt uses
// to keep the X-Coraza-Rules-Matched header focused on attack-detection
// rules. Without this, every block response lists 40+ bookkeeping /
// anomaly-init rules (900990, 901100–901400) that fire on every
// request and drown out the useful signal (942100 = libinjection SQLi,
// 941100 = libinjection XSS, etc).
func TestIsAttackRule(t *testing.T) {
	cases := []struct {
		id   int
		want bool
		name string
	}{
		{0, false, "anonymous/action-only rule"},
		{900990, false, "CRS init family"},
		{901100, false, "CRS anomaly-scoring init"},
		{901400, false, "CRS setup tail"},
		{910100, true, "IP reputation"},
		{913100, true, "scanner detection"},
		{920100, true, "protocol enforcement"},
		{930120, true, "LFI path traversal"},
		{932160, true, "RCE unix shell command"},
		{941100, true, "XSS libinjection"},
		{942100, true, "SQLi libinjection"},
		{949110, true, "inbound anomaly threshold (the one that trips the 403)"},
		{980130, true, "correlation score"},
		{990000, false, "just above the attack range — user-custom territory"},
		{1000000, false, "user-custom rule ID"},
	}
	for _, c := range cases {
		if got := isAttackRule(c.id); got != c.want {
			t.Errorf("isAttackRule(%d) = %v, want %v  — %s", c.id, got, c.want, c.name)
		}
	}
}
