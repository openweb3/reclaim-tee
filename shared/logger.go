//go:build !mobile

package shared

import (
	"context"
	"math"
	"os"
	"strings"
	"sync"

	"cloud.google.com/go/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggerConfig holds the configuration for the logger
type LoggerConfig struct {
	ServiceName string // "tee_t" or "tee_k"
	EnclaveMode bool   // true if running in enclave
	Development bool   // true for development mode
}

// Logger wraps zap.Logger with additional context
type Logger struct {
	*zap.Logger
	serviceName string
}

// gcpCore implements zapcore.Core and writes to GCP Cloud Logging
type gcpCore struct {
	logger      *logging.Logger
	serviceName string
	enclaveMode bool
	level       zapcore.Level
	fields      []zap.Field
}

func (c *gcpCore) Enabled(level zapcore.Level) bool {
	return level >= c.level
}

func (c *gcpCore) With(fields []zapcore.Field) zapcore.Core {
	// Convert zapcore.Field to zap.Field (they're compatible)
	zapFields := make([]zap.Field, len(fields))
	for i, f := range fields {
		zapFields[i] = zap.Field(f)
	}
	return &gcpCore{
		logger:      c.logger,
		serviceName: c.serviceName,
		enclaveMode: c.enclaveMode,
		level:       c.level,
		fields:      append(c.fields, zapFields...),
	}
}

func (c *gcpCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c *gcpCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// Convert zap level to GCP severity
	var severity logging.Severity
	switch entry.Level {
	case zapcore.DebugLevel:
		severity = logging.Debug
	case zapcore.InfoLevel:
		severity = logging.Info
	case zapcore.WarnLevel:
		severity = logging.Warning
	case zapcore.ErrorLevel:
		severity = logging.Error
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		severity = logging.Critical
	default:
		severity = logging.Default
	}

	// Build payload from fields
	payload := make(map[string]any)
	payload["message"] = entry.Message
	payload["service"] = c.serviceName
	payload["enclave_mode"] = c.enclaveMode

	// Add persistent fields
	for _, f := range c.fields {
		addFieldToPayload(payload, f)
	}

	// Add entry fields
	for _, f := range fields {
		addFieldToPayload(payload, zap.Field(f))
	}

	// Log to GCP
	c.logger.Log(logging.Entry{
		Severity: severity,
		Payload:  payload,
	})

	return nil
}

func (c *gcpCore) Sync() error {
	return c.logger.Flush()
}

func addFieldToPayload(payload map[string]any, field zap.Field) {
	switch field.Type {
	case zapcore.StringType:
		payload[field.Key] = field.String
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		payload[field.Key] = field.Integer
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
		payload[field.Key] = field.Integer
	case zapcore.Float64Type:
		// zap keeps a float field as its IEEE-754 bits, so this is a decode and
		// not a cast: handing Integer through puts 4645666129713923682 where a
		// latency of 0.4 was meant, and a number that is wrong but still reads
		// as a number is the kind of wrong nobody catches in a log query.
		payload[field.Key] = math.Float64frombits(uint64(field.Integer))
	case zapcore.Float32Type:
		payload[field.Key] = math.Float32frombits(uint32(field.Integer))
	case zapcore.BoolType:
		payload[field.Key] = field.Integer != 0
	case zapcore.ErrorType:
		if field.Interface != nil {
			payload[field.Key] = field.Interface.(error).Error()
		}
	default:
		payload[field.Key] = field.Interface
	}
}

// logLevelFromEnv parses LOG_LEVEL (debug|info|warn|error); default info.
func logLevelFromEnv() zapcore.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		return zapcore.DebugLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default: // "info" or unset
		return zapcore.InfoLevel
	}
}

func gcpProjectID() string {
	if p := os.Getenv("GCP_PROJECT_ID"); p != "" {
		return p
	}
	return os.Getenv("GOOGLE_PROJECT_ID")
}

// NewLogger creates a new logger instance based on the configuration.
// Cloud sink selection: AWS SEV-SNP -> CloudWatch; GCP (CS enclave or SEV-SNP)
// with a project ID -> Cloud Logging; otherwise console JSON. Level is from
// LOG_LEVEL (default info), so SEV-SNP TEEs no longer default to debug.
func NewLogger(config LoggerConfig) (*Logger, error) {
	var zapLogger *zap.Logger
	var err error
	level := logLevelFromEnv()

	// Reported platform label and cloud-sink gate: any attested TEE, since
	// config.EnclaveMode alone only covers Confidential Space.
	attested := config.EnclaveMode || IsSEVSNPMode()

	switch {
	case IsAWSSEVSNP():
		// AWS SEV-SNP: ship to CloudWatch Logs via the instance IAM role.
		if core, cerr := newCloudWatchCore(config.ServiceName, level); cerr == nil && core != nil {
			zapLogger = zap.New(core)
		}
	default:
		// GCP Cloud Logging for CS enclaves AND SEV-SNP-on-GCP, when a project
		// ID is set (VM needs an SA with roles/logging.logWriter + cloud scope).
		if pid := gcpProjectID(); pid != "" && attested {
			if client, cerr := logging.NewClient(context.Background(), pid); cerr == nil {
				zapLogger = zap.New(&gcpCore{
					logger:      client.Logger(config.ServiceName),
					serviceName: config.ServiceName,
					enclaveMode: attested,
					level:       level,
				})
			}
		}
	}

	// Console fallback (also the default off-cloud / standalone path).
	if zapLogger == nil {
		zapConfig := zap.NewProductionConfig()
		if config.Development {
			zapConfig = zap.NewDevelopmentConfig()
		}
		zapConfig.Level = zap.NewAtomicLevelAt(level)
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = zapConfig.Build()
		if err != nil {
			return nil, err
		}
	}

	// Add service-specific fields
	zapLogger = zapLogger.With(
		zap.String("service", config.ServiceName),
		zap.Bool("enclave_mode", attested),
	)

	return &Logger{
		Logger:      zapLogger,
		serviceName: config.ServiceName,
	}, nil
}

// NewLoggerFromEnv creates a logger using environment variables. EnclaveMode
// is the Confidential Space signal; SEV-SNP is detected separately in NewLogger.
func NewLoggerFromEnv(serviceName string) (*Logger, error) {
	config := LoggerConfig{
		ServiceName: serviceName,
		EnclaveMode: IsEnclaveMode(),
		Development: GetEnvOrDefault("DEVELOPMENT", "false") == "true",
	}
	return NewLogger(config)
}

// TruncateSessionID returns first 8 chars of session ID for logging (security)
func TruncateSessionID(sessionID string) string {
	if len(sessionID) <= 8 {
		return sessionID
	}
	return sessionID[:8]
}

// Session-aware logging methods (truncates session ID for security)
func (l *Logger) WithSession(sessionID string) *zap.Logger {
	if sessionID == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("sid", TruncateSessionID(sessionID)))
}

// WithSessionFull logs full session ID - use only when absolutely necessary
func (l *Logger) WithSessionFull(sessionID string) *zap.Logger {
	if sessionID == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("session_id", sessionID))
}

// Connection-aware logging methods - DEPRECATED: don't log remote addresses
func (l *Logger) WithConnection(remoteAddr string) *zap.Logger {
	// No longer log remote addresses for privacy
	return l.Logger
}

// Protocol-aware logging methods
func (l *Logger) WithMessageType(msgType string) *zap.Logger {
	if msgType == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("message_type", msgType))
}

// Crypto-aware logging methods
func (l *Logger) WithCryptoOp(operation string) *zap.Logger {
	return l.Logger.With(zap.String("crypto_operation", operation))
}

// Critical error logging - always logs even in enclave mode.
// Synchronously flushes after writing — Critical() callers typically
// follow with os.Exit, so unbuffered semantics are non-negotiable.
// Without the Sync, the "critical" message disappears when the
// process exits before zap's internal writer drains.
func (l *Logger) Critical(msg string, fields ...zap.Field) {
	l.Logger.Error(msg, append(fields, zap.Bool("critical", true))...)
	_ = l.Logger.Sync()
}

// Security event logging - for security-relevant events
func (l *Logger) Security(msg string, fields ...zap.Field) {
	// Security events are always logged regardless of mode
	l.Logger.Warn(msg, append(fields, zap.Bool("security_event", true))...)
}

// Session termination logging
func (l *Logger) SessionTerminated(sessionID string, reason string, fields ...zap.Field) {
	baseFields := []zap.Field{
		zap.String("sid", TruncateSessionID(sessionID)),
		zap.String("termination_reason", reason),
		zap.Bool("session_terminated", true),
	}
	l.Logger.Error("Session terminated", append(baseFields, fields...)...)
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Close closes the logger and flushes any buffered entries
func (l *Logger) Close() error {
	return l.Logger.Sync()
}

// Global logger instances
var (
	DefaultLogger     *Logger
	teetLoggerOnce    sync.Once
	teekLoggerOnce    sync.Once
	defaultTEETLogger *Logger
	defaultTEEKLogger *Logger
)

// GetTEETLogger returns the default TEE_T logger
func GetTEETLogger() *Logger {
	if DefaultLogger != nil {
		return DefaultLogger
	}
	teetLoggerOnce.Do(func() {
		defaultTEETLogger, _ = NewLoggerFromEnv("tee_t")
	})
	return defaultTEETLogger
}

// GetTEEKLogger returns the default TEE_K logger
func GetTEEKLogger() *Logger {
	if DefaultLogger != nil {
		return DefaultLogger
	}
	teekLoggerOnce.Do(func() {
		defaultTEEKLogger, _ = NewLoggerFromEnv("tee_k")
	})
	return defaultTEEKLogger
}

func NewNopLogger() *Logger {
	return &Logger{
		Logger: zap.NewNop(),
	}
}
