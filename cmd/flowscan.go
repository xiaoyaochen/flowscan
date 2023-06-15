package main

import (
	"github.com/alecthomas/kong"
	"github.com/xiaoyaochen/flowscan/pkg/runner"
)

var App struct {
	NmapService runner.NmapServiceCommand `cmd name:"nmap" help:"Input ip:port to Nmap scan"`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
