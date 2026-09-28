package main

import (
	"database/sql"
	"log"
)

// Small wrappers so a handler reads as one line and a database hiccup never
// takes a connection down with it: the error is logged and the caller carries
// on.

func exec(query string, args ...any) sql.Result {
	res, err := db.Exec(query, args...)
	if err != nil {
		log.Printf("sql exec: %v", err)
		return nil
	}
	return res
}

func queryRow(query string, args ...any) *sql.Row {
	return db.QueryRow(query, args...)
}

func query(query string, args ...any) (*sql.Rows, bool) {
	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("sql query: %v", err)
		return nil, false
	}
	return rows, true
}
