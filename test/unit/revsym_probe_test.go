package unit

import (
	"os"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/test/revsym"
)

func TestRevsymProbe(t *testing.T) {
	initArbiters()
	opt := revsym.NewOptions()
	d := revsym.Dump(abt, opt)
	t.Logf("dump lines=%d bytes=%d", len(strings.Split(d, "\n")), len(d))
	os.WriteFile("/root/revsym/probe.txt", []byte(d), 0644)
	d2 := revsym.Dump(abt, opt)
	if diff := revsym.Diff(d, d2, 10); diff != "" {
		t.Fatalf("dump is not deterministic:\n%s", diff)
	}
}
