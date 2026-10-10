//go:build linux && !mobile

package shared

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Wall-clock discipline for the SNP guest. The kernel timekeeping we inherit is
// only as good as its clocksource, and a SEV-SNP guest that falls back to an
// uncalibrated tsc drifts a few seconds per day. That drift is not cosmetic:
// the NitroTPM leaf certificate the TEE attests with is stamped by the
// hypervisor, so a guest whose clock runs behind eventually reads as "not yet
// valid" against a certificate it just issued, every rotation fails, and the
// deployment stops attesting for good. See DeployClockDiscipline for the entry
// point the broker calls.
//
// The reference is Amazon Time Sync Service, a link-local NTP server AWS
// documents for exactly this: no internet egress required, and the same
// substrate that already serves IMDS on this guest.
const (
	// amazonTimeSync is the link-local Amazon Time Sync Service endpoint. It
	// answers on UDP 123 without any internet route, so clock discipline needs
	// no egress rule and no change to the deployment's network posture.
	amazonTimeSync = "169.254.169.123:123"

	// ntpEpochOffset is the seconds between the NTP epoch (1900-01-01) and the
	// Unix epoch. NTP timestamps count from 1900, Go's from 1970.
	ntpEpochOffset = 2208988800

	// clockResyncInterval is how often the wall clock is re-disciplined. Drift
	// on this platform is seconds per day, so a coarse interval leaves a
	// negligible residual while costing one link-local round trip per period.
	clockResyncInterval = 15 * time.Minute

	// clockQueryTimeout bounds a single exchange. The reference is link-local,
	// so a healthy reply is sub-millisecond; anything slower means the path is
	// broken and waiting longer only delays the next attempt.
	clockQueryTimeout = 3 * time.Second

	// maxClockStep bounds a single correction. Without it, one malformed or
	// hostile reply could move the guest clock by an arbitrary amount, which is
	// a far worse failure than the drift being corrected: the clock gates
	// receipt freshness and attestation validity. Real drift is seconds per
	// day, so a generous ceiling still never rejects a legitimate correction.
	maxClockStep = 10 * time.Minute
)

// DeployClockDiscipline corrects the guest wall clock from the platform time
// source and keeps correcting it for the life of the process. It is meant to
// run in the attestation broker: that process is root (it owns /dev/sev-guest
// and /dev/tpm0, and already reboots the guest on a wedged channel), whereas
// the TEE app itself is unprivileged and cannot set the clock at all.
//
// The first exchange is synchronous: the broker must not answer its first
// attestation request while the clock is still uncorrected, or the app's
// initial NitroTPM certificate can be verified against a behind clock and kill
// the app. Only the periodic resyncs run, in the background, for the life of
// the process.
//
// Safe to call on a guest whose clock is already correct — that is the normal
// case — and safe to call when no time source is reachable, in which case it
// leaves the clock alone rather than guessing. A nil logger is tolerated so a
// broker that could not build one still gets its clock disciplined.
func DeployClockDiscipline(logger *Logger) {
	// A correction that cannot be measured must never be guessed at, so a
	// failure is logged (when there is a logger) and the clock left alone: the
	// epoch already on record is still serving and the next tick retries.
	resync := func(what string) {
		if err := syncClockOnce(); err != nil && logger != nil {
			logger.Warn(what+" failed; wall clock unchanged", zap.Error(err))
		}
	}
	resync("initial clock sync")
	go func() {
		for range time.Tick(clockResyncInterval) {
			resync("clock resync")
		}
	}()
}

// syncClockOnce performs one SNTP exchange and applies the resulting step.
func syncClockOnce() error {
	offset, err := querySNTP(amazonTimeSync, clockQueryTimeout)
	if err != nil {
		return err
	}
	return applyClockStep(offset)
}

// applyClockStep moves the wall clock by offset, returning nil when the clock
// already agrees with the reference and no syscall is needed. It uses
// clock_settime rather than a gradual slew: the clock is behind by seconds, not
// microseconds, and slewing would leave the guest still behind for minutes after
// each correction — which is the window in which attestation fails.
// CLOCK_REALTIME is stepped (never CLOCK_MONOTONIC), so Go's monotonic
// deadlines and the refresh loop's own timers keep measuring real elapsed time
// across the correction.
func applyClockStep(offset time.Duration) error {
	if offset == 0 {
		return nil
	}
	if offset > maxClockStep || offset < -maxClockStep {
		return fmt.Errorf("refusing clock step of %v: exceeds %v ceiling", offset, maxClockStep)
	}
	tspec := unix.NsecToTimespec(time.Now().Add(offset).UnixNano())
	return unix.ClockSettime(unix.CLOCK_REALTIME, &tspec)
}

// querySNTP returns the signed offset between the local clock and the remote
// reference: positive when the local clock is behind. The exchange is the
// standard four-timestamp SNTP handshake, using the server's transmit and
// receive stamps against our own to cancel out round-trip latency.
func querySNTP(server string, timeout time.Duration) (time.Duration, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	// A 48-byte client packet with the transmit field already filled is a
	// complete request; SNTP servers answer a zeroed packet the same way, but
	// stamping it lets the server echo back our own transmit time, which is
	// what makes the offset calculation below verifiable.
	req := make([]byte, 48)
	req[0] = 0x23 // LI 0, VN 4, Mode 3 (client)
	t1 := time.Now()
	putNTPTimestamp(req[40:48], t1)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, err
	}
	t4 := time.Now()

	if mode := resp[0] & 0x7; mode != 4 {
		return 0, fmt.Errorf("sntp: reply mode %d is not server", mode)
	}
	// LI 3 and stratum > 15 both mean the server itself has no synchronized
	// reference, so its timestamps are placeholders. Stepping the clock on
	// their word could push this guest behind the NitroTPM NotBefore — the
	// very failure this discipline exists to prevent — so refuse the reply
	// and let the next tick try again.
	if li := resp[0] >> 6; li == 3 {
		return 0, fmt.Errorf("sntp: server reports an unsynchronized clock (LI 3)")
	}
	if resp[1] == 0 {
		return 0, fmt.Errorf("sntp: server reports Kiss-o'-Death")
	}
	if resp[1] > 15 {
		return 0, fmt.Errorf("sntp: reply stratum %d is not a synchronized source", resp[1])
	}
	// The server echoes our transmit stamp in the origin field. A reply whose
	// origin does not match is a stale or forged packet off the wire, not our
	// answer, and trusting it would let a single injected packet set the clock.
	if !bytes.Equal(resp[24:32], req[40:48]) {
		return 0, fmt.Errorf("sntp: origin stamp mismatch (replayed or forged reply)")
	}

	t2 := ntpTimestamp(resp[32:40]) // server receive
	t3 := ntpTimestamp(resp[40:48]) // server transmit
	return sntpOffset(t1, t2, t3, t4), nil
}

// sntpOffset is the standard SNTP offset/thumbprint calculation:
// theta = ((T2 - T1) + (T3 - T4)) / 2. Returned as a positive duration when the
// local clock is behind the reference.
func sntpOffset(t1, t2, t3, t4 time.Time) time.Duration {
	// Work in integer nanoseconds: the halves can each be a few hundred ms and
	// a float64 cannot hold a day-scale unix time with the precision this needs.
	return (t2.Sub(t1) + t3.Sub(t4)) / 2
}

// ntpTimestamp decodes a 64-bit NTP timestamp: 32-bit seconds since 1900 in the
// high half, a 2^-32-second fraction in the low half. The seconds field wraps
// in 2036, so the decoded instant is shifted into the era the local clock
// currently lives in — otherwise a post-rollover reply reads as a date near
// 1900, the offset exceeds maxClockStep, and the clock never gets corrected
// again. The two candidates are 136 years apart, so at most one shift is ever
// needed.
func ntpTimestamp(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	// Integer arithmetic throughout: the fraction is a 32-bit binary point, and
	// float64 cannot hold a day-scale unix time with the precision this needs.
	nsec := int64(frac) * 1e9 / (1 << 32)
	unix := int64(sec) - ntpEpochOffset
	now := time.Now().Unix()
	for now-unix > 1<<31 {
		unix += 1 << 32
	}
	for unix-now > 1<<31 {
		unix -= 1 << 32
	}
	return time.Unix(unix, nsec)
}

// putNTPTimestamp encodes t into the 64-bit NTP layout used by both the
// transmit field we fill and the origin field we check.
func putNTPTimestamp(b []byte, t time.Time) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32(int64(t.Nanosecond()) * (1 << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], sec)
	binary.BigEndian.PutUint32(b[4:8], frac)
}
