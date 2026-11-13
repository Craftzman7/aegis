// Command aegis-agent is the Aegis on-box Linux security agent.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/agent"
	"github.com/aegis-soc/aegis/agent/internal/event"
	"github.com/aegis-soc/aegis/agent/internal/policy"
	"github.com/aegis-soc/aegis/agent/internal/sigma"
	"github.com/aegis-soc/aegis/agent/internal/transport"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = `aegis-agent ` + "%s" + `

Usage:
  aegis-agent enroll --server URL --token TOKEN [--data-dir DIR] [--config FILE]
  aegis-agent run [--config FILE] [--server URL] [--data-dir DIR] [--log-level LEVEL]
  aegis-agent test-rule --rule FILE.yml --events FILE.jsonl
  aegis-agent version

Config (default /etc/aegis/agent.yaml): server_url, data_dir, log_level.
Environment overrides: AEGIS_SERVER_URL, AEGIS_DATA_DIR, AEGIS_LOG_LEVEL.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("aegis-agent %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "test-rule":
		err = cmdTestRule(os.Args[2:])
	case "help", "--help", "-h":
		fmt.Printf(usage, version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type commonFlags struct{ config, server, dataDir, logLevel string }

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", envOr("AEGIS_CONFIG", agent.DefaultConfigPath), "config file")
	fs.StringVar(&c.server, "server", "", "server URL (overrides config)")
	fs.StringVar(&c.dataDir, "data-dir", "", "data directory (overrides config)")
	fs.StringVar(&c.logLevel, "log-level", "", "log level (overrides config)")
}

func (c *commonFlags) load() (agent.Config, error) {
	cfg, err := agent.LoadConfig(c.config)
	if err != nil {
		return cfg, err
	}
	if c.server != "" {
		cfg.ServerURL = c.server
	}
	if c.dataDir != "" {
		cfg.DataDir = c.dataDir
	}
	if c.logLevel != "" {
		cfg.LogLevel = c.logLevel
	}
	return cfg, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	token := fs.String("token", os.Getenv("AEGIS_ENROLL_TOKEN"), "one-time enrollment token")
	fs.Parse(args)
	cfg, err := cf.load()
	if err != nil {
		return err
	}
	if cfg.ServerURL == "" || *token == "" {
		return fmt.Errorf("--server and --token are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, env, err := transport.Enroll(ctx, cfg.ServerURL, *token, cfg.DataDir, version)
	if err != nil {
		return err
	}
	pub, _ := id.ServerPub()
	pm := policy.NewManager(pub, id.HostID, cfg.DataDir+"/policy.json")
	p, err := pm.Apply(env)
	if err != nil {
		return fmt.Errorf("initial policy: %w", err)
	}
	fmt.Printf("enrolled: host_id=%s policy_version=%d data_dir=%s\n", id.HostID, p.Version, cfg.DataDir)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	fs.Parse(args)
	cfg, err := cf.load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, cfg, version)
}

// cmdTestRule evaluates a Sigma rule against a JSONL file of events. Each line
// is a JSON object using Sigma field names (Image, CommandLine, ...) and an
// optional "logsource": {"category": "...", "service": "..."}; a missing
// logsource matches any rule logsource.
func cmdTestRule(args []string) error {
	fs := flag.NewFlagSet("test-rule", flag.ExitOnError)
	rulePath := fs.String("rule", "", "Sigma rule YAML file")
	eventsPath := fs.String("events", "", "JSONL events file")
	fs.Parse(args)
	if *rulePath == "" || *eventsPath == "" {
		return fmt.Errorf("--rule and --events are required")
	}
	y, err := os.ReadFile(*rulePath)
	if err != nil {
		return err
	}
	set, errs := sigma.Load([]sigma.Source{{ID: *rulePath, Status: sigma.StatusActive, YAML: string(y)}})
	if len(errs) > 0 {
		return fmt.Errorf("rule failed to load: %s", errs[0].Error)
	}
	f, err := os.Open(*eventsPath)
	if err != nil {
		return err
	}
	defer f.Close()
	r := set.Rules()[0]
	fmt.Printf("rule: %s (%s) level=%s severity=%s tags=%v\n", r.Title, r.ID, r.Level, r.Severity, r.AttackTags)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	line, total, matched := 0, 0, 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		total++
		if len(set.Evaluate(context.Background(), &ev)) > 0 {
			matched++
			fmt.Printf("MATCH line %d: %s\n", line, summarize(&ev))
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	fmt.Printf("%d of %d events matched\n", matched, total)
	if matched == 0 {
		os.Exit(3)
	}
	return nil
}

func summarize(e *event.Event) string {
	for _, s := range []string{e.CommandLine, e.TargetFilename, e.Image, e.Message} {
		if s != "" {
			return s
		}
	}
	return fmt.Sprintf("%+v", *e)
}
