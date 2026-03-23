package main

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

var (
	globalCtx         context.Context
	configPaths       []string
	configDirectories []string
	workingDir        string
	disableColor      bool
)

type cliArgs struct {
	ConfigPaths       []string   `short:"c" name:"config" help:"Set configuration file path."`
	ConfigDirectories []string   `short:"C" name:"config-directory" help:"Set configuration directory path."`
	WorkingDir        string     `short:"D" name:"directory" help:"Set working directory."`
	DisableColor      bool       `name:"disable-color" help:"Disable color output."`
	Run               runCommand `cmd:"" help:"Run service."`
	Check             checkCmd   `cmd:"" help:"Check configuration."`
	Format            formatCmd  `cmd:"" help:"Format configuration."`
	Version           versionCmd `cmd:"" help:"Print current version of srsc."`
}

type runCommand struct{}

type checkCmd struct{}

type formatCmd struct {
	Write bool `short:"w" name:"write" help:"Write result to source file instead of stdout."`
}

type versionCmd struct {
	NameOnly bool `short:"n" name:"name" help:"Print version name only."`
}

func (c *runCommand) Run() error {
	return run()
}

func (c *checkCmd) Run() error {
	return check()
}

func (c *formatCmd) Run() error {
	commandFormatFlagWrite = c.Write
	return format()
}

func (c *versionCmd) Run() error {
	return printVersion(c.NameOnly)
}

func executeMain() error {
	args := &cliArgs{}
	parser, err := kong.New(args, kong.Name("srsc"))
	if err != nil {
		return err
	}
	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	configPaths = normalizePathList(args.ConfigPaths)
	configDirectories = normalizePathList(args.ConfigDirectories)
	workingDir = strings.TrimSpace(args.WorkingDir)
	disableColor = args.DisableColor
	if err := preRun(); err != nil {
		return err
	}
	return ctx.Run()
}

func preRun() error {
	globalCtx = context.Background()
	sudoUser := os.Getenv("SUDO_USER")
	sudoUID, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
	sudoGID, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
	if sudoUID == 0 && sudoGID == 0 && sudoUser != "" {
		sudoUserObject, _ := user.Lookup(sudoUser)
		if sudoUserObject != nil {
			sudoUID, _ = strconv.Atoi(sudoUserObject.Uid)
			sudoGID, _ = strconv.Atoi(sudoUserObject.Gid)
		}
	}
	if sudoUID > 0 && sudoGID > 0 {
		globalCtx = filemanager.WithDefault(globalCtx, "", "", sudoUID, sudoGID)
	}
	if disableColor {
		log.SetStdLogger(log.NewDefaultFactory(globalCtx, log.Formatter{BaseTime: time.Now(), DisableColors: true}, os.Stderr, "", nil, false).Logger())
	}
	if workingDir != "" {
		absPath, err := filepath.Abs(workingDir)
		if err != nil {
			return err
		}
		info, err := os.Stat(absPath)
		switch {
		case err == nil && !info.IsDir():
			return errors.New("working directory path is not a directory: " + absPath)
		case errors.Is(err, os.ErrNotExist):
			if err := filemanager.MkdirAll(globalCtx, absPath, 0o777); err != nil {
				return err
			}
		case err != nil:
			return err
		}
		if err := os.Chdir(absPath); err != nil {
			return err
		}
	}
	if len(configPaths) == 0 && len(configDirectories) == 0 {
		configPaths = []string{"config.json"}
	}
	globalCtx = service.ContextWith(globalCtx, deprecated.NewStderrManager(log.StdLogger()))
	globalCtx = box.Context(globalCtx, inbound.NewRegistry(), outbound.NewRegistry(), endpoint.NewRegistry(), dns.NewTransportRegistry(), boxService.NewRegistry(), certificate.NewRegistry())
	return nil
}

func normalizePathList(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}
