package settings

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/stretchr/testify/assert"
)

// Proves the ACTUAL rehearsal config.json resolves to ARMED gates through the real
// enforce* path (same order as SetupConfig: net defaults -> config file -> enforce).
func TestRehearsalConfigArmsGates(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("REHEARSAL_CONFIG"))
	if err != nil {
		t.Skip("REHEARSAL_CONFIG not set")
	}
	base := config.GetDefaultParams()
	base.RegNet()
	wrap := struct{ Configuration config.Configuration }{Configuration: *base}
	assert.NoError(t, json.Unmarshal(raw, &wrap))
	c := &wrap.Configuration

	enforceCrossChainUTXORestrictionHeights(c)
	enforceStrictMoneyAndRollbackHeights(c)

	t.Logf("ActiveNet=%q Arm=%v strict=%d freeze=%d restrict=%d revised=%d",
		c.ActiveNet, c.ArmIncidentGates, c.StrictMoneyRangeHeight,
		c.CrossChainUTXOFreezeHeight, c.CrossChainUTXORestrictionHeight,
		c.RevisedDPoSRewardHeight)

	assert.True(t, c.ArmIncidentGates, "rehearsal config must set ArmIncidentGates")
	assert.Equal(t, uint32(300), c.StrictMoneyRangeHeight, "strict-money gate must be ARMED, not Disabled")
	assert.Equal(t, uint32(250), c.CrossChainUTXOFreezeHeight)
	assert.Equal(t, uint32(260), c.CrossChainUTXORestrictionHeight)
	assert.Equal(t, uint32(300), c.RevisedDPoSRewardHeight)
	assert.NotEqual(t, config.DisabledStrictMoneyRangeHeight, c.StrictMoneyRangeHeight)
}
