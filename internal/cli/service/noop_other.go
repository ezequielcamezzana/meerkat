//go:build !darwin && !linux

package service

func NewInstaller() Installer { return &noopInstaller{} }
