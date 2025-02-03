package llmfs

import (
	"fmt"
	"strings"
)

// buildFTSMatchQuery returns a sub-select for an FTS table, matching 'searchTerm*'.
func buildFTSMatchQuery(tableName, column, searchTerm, paramKey string) (string, map[string]interface{}) {
	// Build the match value as: "search term"*
	paramValue := fmt.Sprintf("\"%s\"*", searchTerm)
	// Use the provided key with a colon prefix in the query.
	query := fmt.Sprintf(`SELECT rowid AS id FROM %s WHERE %s MATCH :%s`, tableName, column, paramKey)
	params := map[string]interface{}{
		":" + paramKey: paramValue,
	}
	return query, params
}

// buildMatchIntersectionQuery returns a combined subquery (with INTERSECT) and a parameters map.
func buildMatchIntersectionQuery(
	pathExactly, pathContains, pathBegins, pathEnds,
	descContains, contentContains string,
) (string, map[string]interface{}) {
	subqueries := []string{}
	params := make(map[string]interface{})
	paramCounter := 0

	// Helper to generate a unique parameter key.
	newKey := func() string {
		key := fmt.Sprintf("p%d", paramCounter)
		paramCounter++
		return key
	}

	if pathExactly != "" {
		key := newKey()
		subqueries = append(subqueries, "SELECT rowid AS id FROM filesystem WHERE path = :"+key)
		params[":"+key] = pathExactly
	}
	if pathContains != "" {
		key := newKey()
		q, p := buildFTSMatchQuery("filesystem_word_fts", "path", pathContains, key)
		subqueries = append(subqueries, q)
		for k, v := range p {
			params[k] = v
		}
	}
	if pathBegins != "" {
		key := newKey()
		q, p := buildFTSMatchQuery("filesystem_path_fts", "path", pathBegins, key)
		subqueries = append(subqueries, q)
		for k, v := range p {
			params[k] = v
		}
	}
	if pathEnds != "" {
		key := newKey()
		// Reverse the search term for the reverse index.
		q, p := buildFTSMatchQuery("filesystem_rev_path_fts", "reversed_path", ReverseString(pathEnds), key)
		subqueries = append(subqueries, q)
		for k, v := range p {
			params[k] = v
		}
	}
	if descContains != "" {
		key := newKey()
		q, p := buildFTSMatchQuery("filesystem_word_fts", "description", descContains, key)
		subqueries = append(subqueries, q)
		for k, v := range p {
			params[k] = v
		}
	}
	if contentContains != "" {
		key := newKey()
		q, p := buildFTSMatchQuery("filesystem_word_fts", "content", contentContains, key)
		subqueries = append(subqueries, q)
		for k, v := range p {
			params[k] = v
		}
	}

	if len(subqueries) == 0 {
		return "", nil
	}
	if len(subqueries) == 1 {
		return subqueries[0], params
	}
	// Combine them with INTERSECT.
	combinedQuery := strings.Join(subqueries, "\nINTERSECT\n")
	return combinedQuery, params
}

func ReverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
