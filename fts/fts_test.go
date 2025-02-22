package fts_test

import (
	"fmt"
	"testing"

	"github.com/dropsite-ai/llmfs/fts"
	"github.com/stretchr/testify/require"
)

func TestBuildFTSMatchQuery(t *testing.T) {
	tableName := "my_fts_table"
	column := "my_column"
	searchTerm := "someTerm"
	paramKey := "p1"

	query, params := fts.BuildFTSMatchQuery(tableName, column, searchTerm, paramKey)

	expectedQuery := fmt.Sprintf(`SELECT rowid AS id FROM %s WHERE %s MATCH :%s`, tableName, column, paramKey)
	require.Equal(t, expectedQuery, query, "Query string mismatch")

	// Expect the parameter to be ":p1" => "\"someTerm\"*"
	require.Len(t, params, 1)
	require.Equal(t, `"someTerm"*`, params[":"+paramKey], "Parameter value mismatch")
}

func TestReverseString(t *testing.T) {
	require.Equal(t, "cba", fts.ReverseString("abc"), "Reverse of 'abc' should be 'cba'")
	require.Equal(t, "", fts.ReverseString(""), "Reverse of empty string should be empty")
	require.Equal(t, "1", fts.ReverseString("1"), "Single character should remain the same")
	require.Equal(t, "olleh dlrow", fts.ReverseString("world hello"), "Sentence reversed")
}

func TestBuildMatchIntersectionQuery_AllEmpty(t *testing.T) {
	// No filters => expect empty subquery and nil params
	subquery, params := fts.BuildMatchIntersectionQuery("", "", "", "", "", "")
	require.Empty(t, subquery, "Expected empty query when all search terms are empty")
	require.Nil(t, params, "Expected nil parameters when all search terms are empty")
}

func TestBuildMatchIntersectionQuery_SinglePathExactly(t *testing.T) {
	// Only pathExactly => single subquery for path exactly
	subquery, params := fts.BuildMatchIntersectionQuery("/exact/path", "", "", "", "", "")
	require.NotEmpty(t, subquery, "Expected a non-empty subquery for pathExactly")
	require.Contains(t, subquery, "WHERE path = :p0", "Should match path exactly in the query")

	require.Len(t, params, 1, "One parameter expected")
	require.Equal(t, "/exact/path", params[":p0"], "Parameter should match the pathExactly value")
}

func TestBuildMatchIntersectionQuery_SinglePathContains(t *testing.T) {
	// Only pathContains => single FTS query on filesystem_word_fts
	subquery, params := fts.BuildMatchIntersectionQuery("", "containsVal", "", "", "", "")
	require.NotEmpty(t, subquery, "Expected a non-empty subquery for pathContains")
	require.Contains(t, subquery, "FROM filesystem_word_fts", "Should query the word FTS table for path")
	require.Contains(t, subquery, "path MATCH :p0", "Should match path in the FTS query")

	require.Len(t, params, 1)
	require.Equal(t, `"containsVal"*`, params[":p0"])
}

func TestBuildMatchIntersectionQuery_PathBegins(t *testing.T) {
	subquery, params := fts.BuildMatchIntersectionQuery("", "", "startVal", "", "", "")
	require.NotEmpty(t, subquery)
	require.Contains(t, subquery, "FROM filesystem_path_fts", "Should query filesystem_path_fts for begins-with")
	require.Contains(t, subquery, "MATCH :p0")

	require.Len(t, params, 1)
	require.Equal(t, `"startVal"*`, params[":p0"])
}

func TestBuildMatchIntersectionQuery_PathEnds(t *testing.T) {
	subquery, params := fts.BuildMatchIntersectionQuery("", "", "", "finishVal", "", "")
	require.NotEmpty(t, subquery)
	require.Contains(t, subquery, "FROM filesystem_rev_path_fts", "Should query reverse path FTS for ends-with")
	require.Contains(t, subquery, "reversed_path MATCH :p0")

	require.Len(t, params, 1)
	// The reversed string of "finishVal" is "lavhsinif" etc. Check:
	expectedParam := fmt.Sprintf(`"%s"*`, fts.ReverseString("finishVal"))
	require.Equal(t, expectedParam, params[":p0"])
}

func TestBuildMatchIntersectionQuery_DescContains(t *testing.T) {
	subquery, params := fts.BuildMatchIntersectionQuery("", "", "", "", "descVal", "")
	require.NotEmpty(t, subquery)
	require.Contains(t, subquery, "FROM filesystem_word_fts", "Description uses the word FTS table")
	require.Contains(t, subquery, "description MATCH :p0")

	require.Len(t, params, 1)
	require.Equal(t, `"descVal"*`, params[":p0"])
}

func TestBuildMatchIntersectionQuery_ContentContains(t *testing.T) {
	subquery, params := fts.BuildMatchIntersectionQuery("", "", "", "", "", "abc123")
	require.NotEmpty(t, subquery)
	require.Contains(t, subquery, "FROM filesystem_word_fts", "Content uses the word FTS table")
	require.Contains(t, subquery, "content MATCH :p0")

	require.Len(t, params, 1)
	require.Equal(t, `"abc123"*`, params[":p0"])
}

func TestBuildMatchIntersectionQuery_MultipleCriteria(t *testing.T) {
	// pathContains + descContains => we get an INTERSECT of two queries
	subquery, params := fts.BuildMatchIntersectionQuery("", "myPath", "", "", "myDesc", "")
	require.NotEmpty(t, subquery)

	// Expect two subqueries joined by INTERSECT:
	//   SELECT rowid AS id FROM filesystem_word_fts WHERE path MATCH :p0
	// INTERSECT
	//   SELECT rowid AS id FROM filesystem_word_fts WHERE description MATCH :p1
	require.Contains(t, subquery, "INTERSECT")
	require.Contains(t, subquery, "path MATCH :p0")
	require.Contains(t, subquery, "description MATCH :p1")

	require.Len(t, params, 2)
	require.Equal(t, `"myPath"*`, params[":p0"])
	require.Equal(t, `"myDesc"*`, params[":p1"])
}
