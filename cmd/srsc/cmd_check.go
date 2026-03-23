package main

import (
	"context"

	"github.com/iantsysog/sing-rule"
)

func check() error {
	options, err := readConfigAndMerge()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(globalCtx)
	defer cancel()
	instance, err := srsc.NewServer(srsc.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return err
	}
	return instance.Close()
}
