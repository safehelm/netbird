package net

import (
	"os"
	"testing"
)

func TestRelayPaceBytes(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		env  string
		want int
	}{
		{"unset", false, "", 0},
		{"empty", true, "", 0},
		{"zero", true, "0", 0},
		{"a rate", true, "700", 87500000},
		{"not a number", true, "fast", 0},
		{"negative", true, "-5", 0},
		{"over what the kernel takes", true, "999999", maxRelayPaceMbit * 1000 * 1000 / 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(relayPaceEnv, c.env)
			} else {
				t.Setenv(relayPaceEnv, "")
				os.Unsetenv(relayPaceEnv)
			}
			if got := relayPaceBytes(); got != c.want {
				t.Fatalf("relayPaceBytes() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestPrepareRelayPacing(t *testing.T) {
	lookup := func() (string, bool) { return os.LookupEnv(quicBatchedSendsEnv) }

	t.Run("no pacing asked leaves the library alone", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "0")
		t.Setenv(quicBatchedSendsEnv, "")
		os.Unsetenv(quicBatchedSendsEnv)
		PrepareRelayPacing()
		if v, set := lookup(); set {
			t.Fatalf("%s was set to %q with no pacing asked", quicBatchedSendsEnv, v)
		}
	})
	t.Run("pacing asked turns batched sends off", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "700")
		t.Setenv(quicBatchedSendsEnv, "")
		os.Unsetenv(quicBatchedSendsEnv)
		PrepareRelayPacing()
		if v, set := lookup(); !set || v != "true" {
			t.Fatalf("%s = %q (set %v), want true", quicBatchedSendsEnv, v, set)
		}
	})
	t.Run("what the environment says stands", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "700")
		t.Setenv(quicBatchedSendsEnv, "false")
		PrepareRelayPacing()
		if v, _ := lookup(); v != "false" {
			t.Fatalf("%s = %q, want the environment's false", quicBatchedSendsEnv, v)
		}
	})
}
