//go:build !generate

package main

import "github.com/sagernet/sing-box/log"

func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}

func runMain() error {
	return executeMain()
}
