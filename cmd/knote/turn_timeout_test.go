package main

import (
	"testing"
	"time"

	"github.com/zzqDeco/knote/internal/runtime"
)

func TestConfiguredTurnTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", want: runtime.DefaultTurnTimeout},
		{name: "override", value: "45s", want: 45 * time.Second},
		{name: "zero", value: "0s", wantErr: true},
		{name: "negative", value: "-1s", wantErr: true},
		{name: "invalid", value: "soon", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("KNOTE_TURN_TIMEOUT", test.value)
			got, err := configuredTurnTimeout()
			if test.wantErr {
				if err == nil {
					t.Fatalf("configuredTurnTimeout() = %s, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("configuredTurnTimeout() = %s, want %s", got, test.want)
			}
		})
	}
}
