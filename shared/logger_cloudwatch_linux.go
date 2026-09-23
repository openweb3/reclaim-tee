//go:build linux && !mobile

package shared

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"go.uber.org/zap/zapcore"
)

// isAlreadyExists reports the one creation failure that is not a problem: a log
// group or stream this deployment (or a previous boot of it) already made.
func isAlreadyExists(err error) bool {
	var exists *cwtypes.ResourceAlreadyExistsException
	return errors.As(err, &exists)
}

// cwShipper owns the CloudWatch client + log group/stream + an async batching
// queue, shared across With()-derived cores.
type cwShipper struct {
	client *cloudwatchlogs.Client
	group  string
	stream string
	ch     chan cwtypes.InputLogEvent

	// The counters exist because nothing else about a broken sink is observable:
	// the app must never block on its logger, so a failed ship is a drop, and the
	// only channel that does not depend on the sink working is stderr.
	mu            sync.Mutex
	failedShips   uint64
	droppedEvents uint64
	lastComplain  time.Time
}

// complain reports a broken sink on stderr, at most once a minute. Console
// output is what survives a sink that cannot ship, so a TEE whose logs are being
// discarded says so on the serial console rather than looking silent and healthy
// — the state that hid this deployment's attestation failures until the TEE went
// dark for other reasons.
func (s *cwShipper) complain(msg string) {
	s.mu.Lock()
	s.failedShips++
	failed, dropped := s.failedShips, s.droppedEvents
	quiet := time.Since(s.lastComplain) < time.Minute
	if !quiet {
		s.lastComplain = time.Now()
	}
	s.mu.Unlock()
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "logger: cloudwatch sink is losing logs after %d failed ships and %d dropped events: %s\n",
		failed, dropped, msg)
}

func (s *cwShipper) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var batch []cwtypes.InputLogEvent
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// PutLogEvents requires chronological order.
		sort.Slice(batch, func(i, j int) bool { return *batch[i].Timestamp < *batch[j].Timestamp })
		if _, err := s.client.PutLogEvents(context.Background(), &cloudwatchlogs.PutLogEventsInput{
			LogGroupName:  &s.group,
			LogStreamName: &s.stream,
			LogEvents:     batch,
		}); err != nil {
			// Deliberately not `_, _ =`: a sink that cannot ship is the difference
			// between an operable TEE and a silent one.
			s.complain("PutLogEvents: " + err.Error())
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= 256 { // well under the 10k/1MB PutLogEvents limits
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// cloudWatchCore is a zapcore.Core that JSON-encodes each entry and ships it to
// CloudWatch Logs via the shipper's async queue. Used by the AWS SEV-SNP TEE,
// authenticating with the instance's IAM role (default credential chain / IMDS).
type cloudWatchCore struct {
	level zapcore.Level
	enc   zapcore.Encoder
	sh    *cwShipper
}

func newCloudWatchCore(serviceName string, level zapcore.Level) (zapcore.Core, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	client := cloudwatchlogs.NewFromConfig(cfg)

	group := os.Getenv("CLOUDWATCH_LOG_GROUP")
	if group == "" {
		group = "/reclaim-tee/snp"
	}
	stream := serviceName
	if sa := os.Getenv("SELF_ADDR"); sa != "" {
		stream += "-" + strings.NewReplacer(":", "_", "*", "_").Replace(sa)
	} else if h, _ := os.Hostname(); h != "" {
		stream += "-" + h
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Idempotent setup. Only "already exists" is survivable here: every other
	// failure means this process cannot ship its logs at all, and the caller has
	// to fall back to the console rather than accept a sink that discards
	// everything in silence.
	if _, err := client.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{LogGroupName: &group}); err != nil && !isAlreadyExists(err) {
		return nil, fmt.Errorf("create log group %s: %w", group, err)
	}
	if _, err := client.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{LogGroupName: &group, LogStreamName: &stream}); err != nil && !isAlreadyExists(err) {
		return nil, fmt.Errorf("create log stream %s/%s: %w", group, stream, err)
	}
	// Prove the sink accepts events before the process trusts it. Creating the
	// group and stream proves nothing: an instance with no IAM instance profile
	// (or a role without logs:PutLogEvents) builds this client happily and then
	// fails every ship — which is how a TEE ran with its rotation failures
	// recorded nowhere while its console held only handshake noise.
	probe := "logger: cloudwatch sink online"
	if _, err := client.PutLogEvents(ctx, &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  &group,
		LogStreamName: &stream,
		LogEvents:     []cwtypes.InputLogEvent{{Message: &probe, Timestamp: aws.Int64(time.Now().UnixMilli())}},
	}); err != nil {
		return nil, fmt.Errorf("cloudwatch sink %s/%s cannot ship events: %w", group, stream, err)
	}

	encCfg := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		MessageKey:     "message",
		NameKey:        "logger",
		CallerKey:      "caller",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	sh := &cwShipper{client: client, group: group, stream: stream, ch: make(chan cwtypes.InputLogEvent, 4096)}
	go sh.run()
	return &cloudWatchCore{level: level, enc: zapcore.NewJSONEncoder(encCfg), sh: sh}, nil
}

func (c *cloudWatchCore) Enabled(l zapcore.Level) bool { return l >= c.level }

func (c *cloudWatchCore) With(fields []zapcore.Field) zapcore.Core {
	clone := c.enc.Clone()
	for i := range fields {
		fields[i].AddTo(clone)
	}
	return &cloudWatchCore{level: c.level, enc: clone, sh: c.sh}
}

func (c *cloudWatchCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

func (c *cloudWatchCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	buf, err := c.enc.EncodeEntry(entry, fields)
	if err != nil {
		return err
	}
	msg := strings.TrimRight(buf.String(), "\n")
	buf.Free()
	ev := cwtypes.InputLogEvent{Message: aws.String(msg), Timestamp: aws.Int64(entry.Time.UnixMilli())}
	select {
	case c.sh.ch <- ev:
	default: // queue full — drop rather than block the app
		c.sh.mu.Lock()
		c.sh.droppedEvents++
		c.sh.mu.Unlock()
		c.sh.complain("queue full, event dropped")
	}
	return nil
}

// Sync is best-effort: the shipper flushes on a 1s ticker.
func (c *cloudWatchCore) Sync() error { return nil }
