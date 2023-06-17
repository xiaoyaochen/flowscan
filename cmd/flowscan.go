package main

import (
	"github.com/alecthomas/kong"
	"github.com/xiaoyaochen/flowscan/pkg/runner"
)

var App struct {
	NmapService    runner.NmapServiceCommand    `cmd name:"nmap" help:"Input ip:port to Nmap scan"`
	MascsanService runner.MasscanServiceCommand `cmd name:"masscan" help:"Input ip to Nmap scan"`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}