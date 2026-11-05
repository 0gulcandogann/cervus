//go:build unix && !linux

package main

func denyDumps() error { return nil }

func dumpable() (bool, error) { return false, nil }
