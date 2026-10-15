package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// timingNames lists a record's stages, which is what most assertions here are
// about: the order of the intervals is the measurement.
func timingNames(stages []tee.TimingStage) []string {
	names := make([]string, 0, len(stages))
	for _, stage := range stages {
		names = append(names, stage.Name)
	}
	return names
}

func sameTimingNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestChannelRecordsEveryStageOfAnExchange pins what the record of a pooled
// exchange looks like, and what the record of the request that paid for the
// connection looks like. The difference between the two is the whole reason
// cold exists: a request without a dial and a tls stage is a request that
// reused a connection somebody else already paid for.
func TestChannelRecordsEveryStageOfAnExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()
	cm := newTestManager(t)

	run := func() tee.TimingRecord {
		t.Helper()
		tm := tee.NewTimings()
		_, err := cm.Do(
			tee.WithTimings(context.Background(), tm),
			testReq(tee.Request{Method: "GET", Host: hostOf(srv), Path: "/v1/x"}),
			func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		return tm.Close(tee.TimingComplete, nil)
	}

	cold := run()
	if got, want := timingNames(cold.Stages), []string{
		tee.StageAcquire, tee.StageDial, tee.StageWrite, tee.StageTTFB, tee.StageBody,
	}; !sameTimingNames(got, want) {
		t.Errorf("cold stages = %v, want %v", got, want)
	}
	if !cold.Cold {
		t.Error("a request that dialled must record cold")
	}

	warm := run()
	if got, want := timingNames(warm.Stages), []string{
		tee.StageAcquire, tee.StageWrite, tee.StageTTFB, tee.StageBody,
	}; !sameTimingNames(got, want) {
		t.Errorf("warm stages = %v, want %v (a reused connection dials nothing)", got, want)
	}
	if warm.Cold {
		t.Error("a request that reused a pooled connection must not record cold")
	}
}

// TestChannelRecordsTheTLSHandshake pins the stage a trust-store mistake or a
// broken relay chain shows up in. It is a separate test from the plaintext one
// because the scheme is what decides whether the handshake happens at all.
func TestChannelRecordsTheTLSHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	cm, err := NewChannelManager(ChannelConfig{
		Scheme:          "https",
		TLSClientConfig: &tls.Config{RootCAs: roots},
	})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	t.Cleanup(func() { _ = cm.Close() })

	tm := tee.NewTimings()
	host := srv.Listener.Addr().String()
	_, err = cm.Do(
		tee.WithTimings(context.Background(), tm),
		testReq(tee.Request{Method: "GET", Host: host, Path: "/v1/x"}),
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	rec := tm.Close(tee.TimingComplete, nil)
	if got, want := timingNames(rec.Stages), []string{
		tee.StageAcquire, tee.StageDial, tee.StageTLS, tee.StageWrite, tee.StageTTFB, tee.StageBody,
	}; !sameTimingNames(got, want) {
		t.Errorf("stages = %v, want %v", got, want)
	}
	for _, stage := range rec.Stages {
		if stage.Name == tee.StageTLS && stage.Dur <= 0 {
			t.Errorf("%s duration = %v, want a measured handshake", tee.StageTLS, stage.Dur)
		}
	}
}

// TestChannelRecordsAReDial pins what a request that lost a pooled connection
// looks like: the stages it paid for twice carry their totals, and dial is
// there to say why. Two entries for acquire would be the other way to say it,
// and every consumer of a record would then have to decide whether to sum them.
func TestChannelRecordsAReDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Int32
	conn1 := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 1 {
				conn1 <- conn // hand the first accepted socket to the test for resetting
			}
			go serveRawConn(conn)
		}
	}()

	cm, err := NewChannelManager(ChannelConfig{Scheme: "http", AllowPlaintext: true})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	host := ln.Addr().String()
	do := func(ctx context.Context) {
		t.Helper()
		if _, err := cm.Do(ctx,
			testReq(tee.Request{Method: "GET", Host: host, Path: "/v1/x"}),
			func([]byte) error { return nil }); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}

	// The first request dials the connection that the second will find dead.
	do(context.Background())
	first := <-conn1
	if tc, ok := first.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = first.Close()
	time.Sleep(100 * time.Millisecond) // let the RST reach the client socket

	tm := tee.NewTimings()
	do(tee.WithTimings(context.Background(), tm))
	rec := tm.Close(tee.TimingComplete, nil)

	// The dead connection is handed out and written to, refused, and replaced
	// by one this request pays for: acquire and write therefore carry two spans
	// each, and dial says a connection was opened at all.
	if got, want := timingNames(rec.Stages), []string{
		tee.StageAcquire, tee.StageWrite, tee.StageDial, tee.StageTTFB, tee.StageBody,
	}; !sameTimingNames(got, want) {
		t.Errorf("re-dial stages = %v, want %v", got, want)
	}
	if n := accepted.Load(); n != 2 {
		t.Errorf("server accepted %d connections, want 2 (1 original + 1 re-dial)", n)
	}
	if rec.Outcome != tee.TimingComplete {
		t.Errorf("outcome = %v, want complete: the re-dial is what made it complete", rec.Outcome)
	}
}

// TestChannelReportsAFailedExchange pins that a request which never got a
// response still measures the stage it died in, which is the case the
// instrumentation exists for: the failure that used to leave one unattributable
// line behind now leaves a named interval.
func TestChannelReportsAFailedExchange(t *testing.T) {
	// A listener that accepts and then says nothing: the request gets as far as
	// waiting for the response headers, and stays there until the deadline.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var (
		mu   sync.Mutex
		held []net.Conn
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Held open and silent on purpose, so the client parks on the
			// response headers rather than on a closed connection.
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})

	cm, err := NewChannelManager(ChannelConfig{Scheme: "http", AllowPlaintext: true})
	if err != nil {
		t.Fatalf("NewChannelManager: %v", err)
	}
	defer func() { _ = cm.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	tm := tee.NewTimings()
	_, err = cm.Do(tee.WithTimings(ctx, tm),
		testReq(tee.Request{Method: "GET", Host: ln.Addr().String(), Path: "/v1/x"}),
		func([]byte) error { return nil })
	if err == nil {
		t.Fatal("Do returned nil for a silent peer")
	}

	rec := tm.Close(tee.TimingFailed, err)
	if got, want := timingNames(rec.Stages), []string{
		tee.StageAcquire, tee.StageDial, tee.StageWrite, tee.StageTTFB,
	}; !sameTimingNames(got, want) {
		t.Errorf("stages = %v, want %v: the record must say where it stopped", got, want)
	}
	if rec.Err == "" {
		t.Error("a failed record must carry the reason it failed")
	}
}
