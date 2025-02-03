package llmfs

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var FilenameRegexp = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

func RowToFileRecord(row map[string]interface{}, includeContent bool) FileRecord {
	fr := FileRecord{
		ID:          AsInt64(row["id"]),
		Path:        AsString(row["path"]),
		IsDirectory: (AsInt64(row["is_directory"]) == 1),
		Description: AsString(row["description"]),
		CreatedAt:   ParseTime(row["created_at"]),
		UpdatedAt:   ParseTime(row["updated_at"]),
	}
	if includeContent {
		fr.Content = AsString(row["content"])
	}
	return fr
}

func ParseTime(v interface{}) time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		fmt.Printf("Warning: invalid time format for %q: %v\n", s, err)
		return time.Time{}
	}
	return t
}

func AsString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func AsInt64(v interface{}) int64 {
	switch val := v.(type) {
	case nil:
		return 0
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	case string:
		// Attempt to parse string as int64
		parsed, err := strconv.ParseInt(val, 10, 64)
		if err == nil {
			return parsed
		}
		fmt.Printf("Warning: could not parse string %q as int64: %v\n", val, err)
		return 0
	default:
		fmt.Printf("Warning: AsInt64 received an unexpected type: %T\n", v)
		return 0
	}
}

// fileIDPath holds (id, path) for matched records.
type fileIDPath struct {
	ID   int64
	Path string
}

func NilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
