//go:build !linux

package net

// setSocketPacing does nothing: only Linux spaces a socket's packets by a rate set on it.
func setSocketPacing(_ any, _ int) {}

// setSocketSendBuffer does nothing: a socket is paced on Linux alone.
func setSocketSendBuffer(_ any, _ int) {}
