package handlers

// contextKey is used for storing/retrieving the username from context.
type contextKey int

// UsernameKey is the context key for the currently authenticated user.
const UsernameKey contextKey = iota
