package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	cli "gopkg.in/urfave/cli.v1"

	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap-agent/server"

	_ "net/http/pprof"
)

var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
	{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
	{{end}}{{if .Flags}}
FLAGS:
	{{range .Flags}}{{.}}
	{{end}}{{end}}
VERSION:
` + server.Version +
	`{{ "\n"}}`

var log = logging.MustGetLogger("honeytrap-agent")

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func serve(c *cli.Context) error {
	options := []server.OptionFn{
		server.WithToken(),
	}

	if v := c.GlobalString("server"); v != "" {
		options = append(options, server.WithServer(v))
	} else {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("No target server set.")), 1)
		return ec
	}

	if key := c.GlobalString("remote-key"); key != "" {
		options = append(options, server.WithKey(key))
	} else {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("No remote key set.")), 1)
		return ec
	}

	srvr, err := server.New(
		options...,
	)

	if err != nil {
		ec := cli.NewExitError(err.Error(), 1)
		return ec
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := make(chan os.Signal, 1)
		signal.Notify(s, os.Interrupt)
		signal.Notify(s, syscall.SIGTERM)

		select {
		case <-s:
			cancel()
		}
	}()

	srvr.Run(ctx)
	return nil
}

func loadConfig(c *cli.Context) error {
	s := c.String("config")

	if s == "" {
		return nil
	}

	r, err := os.Open(s)
	if err != nil {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("Could not open config file: %s", err.Error())), 1)
		return ec
	}

	defer r.Close()

	config := struct {
		Server    string `toml:"server"`
		RemoteKey string `toml:"remote-key"`
	}{}

	if _, err := toml.DecodeReader(r, &config); err != nil {
		ec := cli.NewExitError(fmt.Errorf(color.RedString("Could not parse config file: %s", err.Error())), 1)
		return ec
	}

	c.Set("server", config.Server)
	c.Set("remote-key", config.RemoteKey)

	return nil
}

func New() *cli.App {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(c.App.Writer,
			`Version: %s
Release-Tag: %s
Commit-ID: %s
`, color.YellowString(server.Version), color.YellowString(server.ReleaseTag), color.YellowString(server.CommitID))
	}

	app := cli.NewApp()
	app.Name = "honeytrap-agent"
	app.Usage = "Honeytrap Agent"
	app.Commands = []cli.Command{}

	app.Before = loadConfig

	app.Action = serve

	app.Flags = append(app.Flags, []cli.Flag{
		cli.StringFlag{
			Name:  "config, f",
			Usage: "configuration from `FILE`",
		},
		cli.StringFlag{
			Name:  "server, s",
			Value: "",
			Usage: "server address",
		},
		cli.StringFlag{
			Name:  "remote-key, k",
			Value: "",
			Usage: "remote key of server",
		},
	}...)

	return app
}
