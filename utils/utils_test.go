package utils_test

import (
	"testing"
	"time"

	"github.com/dropsite-ai/llmfs/utils"
	"github.com/stretchr/testify/require"
)

func TestHelperFunctions(t *testing.T) {
	t.Run("ParseTime valid", func(t *testing.T) {
		ts := utils.ParseTime("2023-01-02 15:04:05")
		require.Equal(t, 2023, ts.Year())
		require.Equal(t, time.January, ts.Month())
		require.Equal(t, 2, ts.Day())
		require.Equal(t, 15, ts.Hour())
	})

	t.Run("ParseTime empty", func(t *testing.T) {
		ts := utils.ParseTime("")
		require.True(t, ts.IsZero(), "empty string => zero time")
	})

	t.Run("AsString nil", func(t *testing.T) {
		require.Equal(t, "", utils.AsString(nil))
	})
	t.Run("AsString string", func(t *testing.T) {
		require.Equal(t, "hello", utils.AsString("hello"))
	})
	t.Run("AsString int64", func(t *testing.T) {
		require.Equal(t, "123", utils.AsString(int64(123)))
	})

	t.Run("AsInt64 nil", func(t *testing.T) {
		require.Equal(t, int64(0), utils.AsInt64(nil))
	})
	t.Run("AsInt64 int64", func(t *testing.T) {
		require.Equal(t, int64(999), utils.AsInt64(int64(999)))
	})
}

// Separate test for invalid time format
func TestParseTimeInvalidFormat(t *testing.T) {
	invalid := utils.ParseTime("Not a real time string")
	require.True(t, invalid.IsZero(), "Should return zero time on invalid parse")
}
