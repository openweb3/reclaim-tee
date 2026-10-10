//go:build linux && !mobile

package shared

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
)

const (
	snpAttestationBrokerServerEnv = "SNP_ATTEST_BROKER_SERVER"
	snpAttestationBrokerFDEnv     = "SNP_ATTEST_BROKER_FD"

	snpAttestationBrokerMaxBound    = 4096
	snpAttestationBrokerMaxEvidence = 4 << 20

	snpAttestationBrokerOpAttest = 1
	snpAttestationBrokerOpReset  = 2
)

var (
	snpAttestationBrokerRequestMagic  = [4]byte{'S', 'A', 'B', '2'}
	snpAttestationBrokerResponseMagic = [4]byte{'S', 'A', 'R', '2'}
)

type awsBrokerEvidence struct {
	nitroTPM  []byte
	legacySEV []byte
	sev2      []byte
}

type awsBrokerGenerator func(bound, appHash []byte) (awsBrokerEvidence, error)
type snpBrokerReset func() error

type snpBrokerRequest struct {
	op      byte
	bound   []byte
	appHash []byte
}

var brokerClient struct {
	sync.Mutex
	initialized bool
	conn        net.Conn
	err         error
}

// RunSNPAttestationBrokerIfRequested turns the current TEE binary into the
// root-only AWS attestation broker when the measured loader requests it. Main
// packages call this before loading configuration or secrets.
func RunSNPAttestationBrokerIfRequested() (bool, error) {
	if os.Getenv(snpAttestationBrokerServerEnv) != "1" {
		return false, nil
	}
	fd, err := parseSNPAttestationBrokerFD()
	if err != nil {
		return true, err
	}
	f := os.NewFile(uintptr(fd), "snp-attestation-broker")
	if f == nil {
		return true, fmt.Errorf("open SNP attestation broker fd %d", fd)
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return true, fmt.Errorf("SNP attestation broker connection: %w", err)
	}
	defer conn.Close()

	// The broker owns the guest's privileged surface, so it is also the only
	// process that can keep the wall clock honest. Left uncorrected, a drifting
	// clocksource eventually puts this guest's clock behind the NitroTPM leaf's
	// NotBefore, and every rotation then fails for good. Run discipline before
	// serving — the first sync is synchronous — so the first attestation is
	// already measured against a sane clock. A logger is wanted but not
	// required: clock discipline must still run on a broker that could not
	// build one.
	logger, _ := NewLoggerFromEnv("tokenhive-tee-broker")
	DeployClockDiscipline(logger)

	return true, serveSNPAttestationBroker(conn, generateAWSBrokerEvidence, resetGuestFromBroker)
}

func hasSNPAttestationBroker() bool {
	return os.Getenv(snpAttestationBrokerFDEnv) != ""
}

func requestAWSBrokerEvidence(bound, appHash []byte) (awsBrokerEvidence, error) {
	brokerClient.Lock()
	defer brokerClient.Unlock()
	initializeBrokerClientLocked()
	if brokerClient.err != nil {
		return awsBrokerEvidence{}, brokerClient.err
	}
	if brokerClient.conn == nil {
		return awsBrokerEvidence{}, fmt.Errorf("SNP attestation broker unavailable")
	}
	return exchangeAWSBrokerEvidence(brokerClient.conn, bound, appHash)
}

func resetGuestThroughSNPAttestationBroker() (bool, error) {
	if !hasSNPAttestationBroker() {
		return false, nil
	}
	brokerClient.Lock()
	defer brokerClient.Unlock()
	initializeBrokerClientLocked()
	if brokerClient.err != nil {
		return true, brokerClient.err
	}
	return true, exchangeSNPBrokerReset(brokerClient.conn)
}

func initializeBrokerClientLocked() {
	if brokerClient.initialized {
		return
	}
	brokerClient.initialized = true
	fd, err := parseSNPAttestationBrokerFD()
	if err != nil {
		brokerClient.err = err
		return
	}
	f := os.NewFile(uintptr(fd), "snp-attestation-client")
	if f == nil {
		brokerClient.err = fmt.Errorf("open SNP attestation broker fd %d", fd)
		return
	}
	brokerClient.conn, brokerClient.err = net.FileConn(f)
	f.Close()
}

func parseSNPAttestationBrokerFD() (int, error) {
	raw := os.Getenv(snpAttestationBrokerFDEnv)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 || fd > 1<<20 {
		return 0, fmt.Errorf("invalid %s %q", snpAttestationBrokerFDEnv, raw)
	}
	return fd, nil
}

func generateAWSBrokerEvidence(bound, appHash []byte) (awsBrokerEvidence, error) {
	bind := sha512.Sum512(bound)
	doc, err := RequestNitroTPMDocument(bind[:], nil, nil)
	if err != nil {
		return awsBrokerEvidence{}, fmt.Errorf("nitrotpm document: %w", err)
	}
	legacy, err := GenerateSEVSNPAttestation(bind)
	if err != nil {
		return awsBrokerEvidence{}, fmt.Errorf("legacy SEV report: %w", err)
	}
	v2Data := awsCombinedV2ReportData(bound, appHash, doc)
	v2, err := GenerateSEVSNPAttestation(v2Data)
	if err != nil {
		return awsBrokerEvidence{}, fmt.Errorf("v2 SEV report: %w", err)
	}
	return awsBrokerEvidence{nitroTPM: doc, legacySEV: legacy, sev2: v2}, nil
}

func resetGuestFromBroker() error {
	syscall.Sync()
	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
}

func serveSNPAttestationBroker(rw io.ReadWriter, generate awsBrokerGenerator, reset snpBrokerReset) error {
	for {
		req, err := readSNPBrokerRequest(rw)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch req.op {
		case snpAttestationBrokerOpAttest:
			evidence, err := generate(req.bound, req.appHash)
			if err != nil {
				if writeErr := writeAWSBrokerError(rw, err); writeErr != nil {
					return writeErr
				}
				continue
			}
			if err := writeAWSBrokerEvidence(rw, evidence); err != nil {
				return err
			}
		case snpAttestationBrokerOpReset:
			if err := reset(); err != nil {
				if writeErr := writeAWSBrokerError(rw, fmt.Errorf("reset guest: %w", err)); writeErr != nil {
					return writeErr
				}
				continue
			}
			if err := writeSNPBrokerOK(rw); err != nil {
				return err
			}
		}
	}
}

func readSNPBrokerRequest(r io.Reader) (snpBrokerRequest, error) {
	var header [4 + 1 + 4 + sha512.Size/2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return snpBrokerRequest{}, err
	}
	if string(header[:4]) != string(snpAttestationBrokerRequestMagic[:]) {
		return snpBrokerRequest{}, fmt.Errorf("invalid SNP attestation broker request magic")
	}
	op := header[4]
	boundLen := binary.BigEndian.Uint32(header[5:9])
	appHash := append([]byte(nil), header[9:]...)
	if op == snpAttestationBrokerOpReset {
		if boundLen != 0 || !allZero(appHash) {
			return snpBrokerRequest{}, fmt.Errorf("invalid SNP attestation broker reset request")
		}
		return snpBrokerRequest{op: op}, nil
	}
	if op != snpAttestationBrokerOpAttest {
		return snpBrokerRequest{}, fmt.Errorf("unknown SNP attestation broker operation %d", op)
	}
	if boundLen == 0 || boundLen > snpAttestationBrokerMaxBound {
		return snpBrokerRequest{}, fmt.Errorf("invalid SNP attestation broker bound length %d", boundLen)
	}
	bound := make([]byte, boundLen)
	if _, err := io.ReadFull(r, bound); err != nil {
		return snpBrokerRequest{}, err
	}
	return snpBrokerRequest{op: op, bound: bound, appHash: appHash}, nil
}

func exchangeAWSBrokerEvidence(rw io.ReadWriter, bound, appHash []byte) (awsBrokerEvidence, error) {
	if len(bound) == 0 || len(bound) > snpAttestationBrokerMaxBound {
		return awsBrokerEvidence{}, fmt.Errorf("invalid SNP attestation broker bound length %d", len(bound))
	}
	if len(appHash) != sha512.Size/2 {
		return awsBrokerEvidence{}, fmt.Errorf("invalid SNP app hash length %d", len(appHash))
	}
	var header [4 + 1 + 4 + sha512.Size/2]byte
	copy(header[:4], snpAttestationBrokerRequestMagic[:])
	header[4] = snpAttestationBrokerOpAttest
	binary.BigEndian.PutUint32(header[5:9], uint32(len(bound)))
	copy(header[9:], appHash)
	if err := writeFull(rw, header[:]); err != nil {
		return awsBrokerEvidence{}, err
	}
	if err := writeFull(rw, bound); err != nil {
		return awsBrokerEvidence{}, err
	}
	return readAWSBrokerResponse(rw)
}

func exchangeSNPBrokerReset(rw io.ReadWriter) error {
	var header [4 + 1 + 4 + sha512.Size/2]byte
	copy(header[:4], snpAttestationBrokerRequestMagic[:])
	header[4] = snpAttestationBrokerOpReset
	if err := writeFull(rw, header[:]); err != nil {
		return err
	}
	var response [5]byte
	if _, err := io.ReadFull(rw, response[:]); err != nil {
		return err
	}
	if string(response[:4]) != string(snpAttestationBrokerResponseMagic[:]) {
		return fmt.Errorf("invalid SNP attestation broker response magic")
	}
	if response[4] == 0 {
		return nil
	}
	return readAWSBrokerError(rw)
}

func readAWSBrokerResponse(r io.Reader) (awsBrokerEvidence, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return awsBrokerEvidence{}, err
	}
	if string(header[:4]) != string(snpAttestationBrokerResponseMagic[:]) {
		return awsBrokerEvidence{}, fmt.Errorf("invalid SNP attestation broker response magic")
	}
	if header[4] != 0 {
		return awsBrokerEvidence{}, readAWSBrokerError(r)
	}

	parts := make([][]byte, 3)
	for i := range parts {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return awsBrokerEvidence{}, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > snpAttestationBrokerMaxEvidence {
			return awsBrokerEvidence{}, fmt.Errorf("invalid SNP attestation evidence length %d", n)
		}
		parts[i] = make([]byte, n)
		if _, err := io.ReadFull(r, parts[i]); err != nil {
			return awsBrokerEvidence{}, err
		}
	}
	return awsBrokerEvidence{nitroTPM: parts[0], legacySEV: parts[1], sev2: parts[2]}, nil
}

func readAWSBrokerError(r io.Reader) error {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return err
	}
	return fmt.Errorf("SNP attestation broker: %s", msg)
}

func writeAWSBrokerEvidence(w io.Writer, evidence awsBrokerEvidence) error {
	parts := [][]byte{evidence.nitroTPM, evidence.legacySEV, evidence.sev2}
	for _, part := range parts {
		if len(part) == 0 || len(part) > snpAttestationBrokerMaxEvidence {
			return fmt.Errorf("invalid SNP attestation evidence length %d", len(part))
		}
	}
	header := append(append([]byte(nil), snpAttestationBrokerResponseMagic[:]...), 0)
	if err := writeFull(w, header); err != nil {
		return err
	}
	for _, part := range parts {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(part)))
		if err := writeFull(w, lenBuf[:]); err != nil {
			return err
		}
		if err := writeFull(w, part); err != nil {
			return err
		}
	}
	return nil
}

func writeAWSBrokerError(w io.Writer, brokerErr error) error {
	msg := []byte(brokerErr.Error())
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	header := append(append([]byte(nil), snpAttestationBrokerResponseMagic[:]...), 1)
	if err := writeFull(w, header); err != nil {
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if err := writeFull(w, lenBuf[:]); err != nil {
		return err
	}
	return writeFull(w, msg)
}

func writeSNPBrokerOK(w io.Writer) error {
	header := append(append([]byte(nil), snpAttestationBrokerResponseMagic[:]...), 0)
	return writeFull(w, header)
}

func allZero(data []byte) bool {
	var combined byte
	for _, b := range data {
		combined |= b
	}
	return combined == 0
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}
