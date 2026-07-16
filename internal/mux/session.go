// Package mux provides a bounded logical-stream multiplexer over one reliable
// authenticated connection. It is an application-layer protocol above ETP/1;
// it does not change the ETP/1 wire format.
package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	protocolVersion = 1
	headerSize      = 8

	frameOpen  = 1
	frameData  = 2
	frameClose = 3
	frameReset = 4

	defaultMaxFramePayload = 16 * 1024
	defaultMaxStreams      = 1024
	defaultStreamBuffer    = 16
	maxResetReason         = 512
)

var (
	// ErrProtocol indicates a malformed or invalid mux frame.
	ErrProtocol = errors.New("mux: invalid frame")
	// ErrClosed indicates that the session or logical stream is closed.
	ErrClosed = errors.New("mux: session closed")
)

// Config bounds one mux session. The two peers must use compatible
// MaxFramePayload values; other values are local resource limits.
type Config struct {
	MaxFramePayload int
	MaxStreams      int
	StreamBuffer    int
}

type normalizedConfig struct {
	maxFramePayload int
	maxStreams      int
	streamBuffer    int
}

func (cfg Config) normalize() (normalizedConfig, error) {
	out := normalizedConfig{
		maxFramePayload: cfg.MaxFramePayload,
		maxStreams:      cfg.MaxStreams,
		streamBuffer:    cfg.StreamBuffer,
	}
	if out.maxFramePayload == 0 {
		out.maxFramePayload = defaultMaxFramePayload
	}
	if out.maxStreams == 0 {
		out.maxStreams = defaultMaxStreams
	}
	if out.streamBuffer == 0 {
		out.streamBuffer = defaultStreamBuffer
	}
	if out.maxFramePayload < 1 || out.maxFramePayload > 65535 {
		return normalizedConfig{}, fmt.Errorf("mux: MaxFramePayload must be between 1 and 65535")
	}
	if out.maxStreams < 1 || out.maxStreams > 1<<20 {
		return normalizedConfig{}, fmt.Errorf("mux: MaxStreams must be between 1 and %d", 1<<20)
	}
	if out.streamBuffer < 1 || out.streamBuffer > 1<<16 {
		return normalizedConfig{}, fmt.Errorf("mux: StreamBuffer must be between 1 and %d", 1<<16)
	}
	return out, nil
}

// Session owns one underlying connection and multiplexes logical Streams over
// it. A client allocates odd stream IDs; a server allocates even IDs.
type Session struct {
	conn net.Conn
	cfg  normalizedConfig

	writeMu sync.Mutex
	mu      sync.Mutex
	streams map[uint32]*Stream

	acceptCh     chan *Stream
	done         chan struct{}
	doneOnce     sync.Once
	closeMu      sync.Mutex
	err          error
	nextID       uint32
	remoteParity uint32
}

// NewSession starts a mux reader on conn. The caller remains responsible for
// selecting and authenticating the underlying connection before this call.
func NewSession(conn net.Conn, cfg Config, client bool) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("mux: nil connection")
	}
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	firstID := uint32(2)
	remoteParity := uint32(1)
	if client {
		firstID = 1
		remoteParity = 2
	}
	s := &Session{
		conn:         conn,
		cfg:          normalized,
		streams:      make(map[uint32]*Stream),
		acceptCh:     make(chan *Stream, normalized.maxStreams),
		done:         make(chan struct{}),
		nextID:       firstID,
		remoteParity: remoteParity,
	}
	go s.readLoop()
	return s, nil
}

// Open creates a logical stream and sends its OPEN frame.
func (s *Session) Open() (net.Conn, error) {
	s.mu.Lock()
	if err := s.sessionErrLocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if len(s.streams) >= s.cfg.maxStreams {
		s.mu.Unlock()
		return nil, fmt.Errorf("mux: maximum streams reached")
	}
	id := s.nextID
	s.nextID += 2
	stream := newStream(s, id)
	s.streams[id] = stream
	s.mu.Unlock()
	if err := s.sendFrame(frameOpen, id, nil); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return stream, nil
}

// Accept waits for the next remotely opened logical stream.
func (s *Session) Accept() (net.Conn, error) {
	select {
	case stream := <-s.acceptCh:
		if stream == nil {
			return nil, s.Err()
		}
		return stream, nil
	case <-s.done:
		return nil, s.Err()
	}
}

// Err returns the terminal session error, or ErrClosed if it was closed
// without a protocol or transport error.
func (s *Session) Err() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.err == nil {
		return ErrClosed
	}
	return s.err
}

// Close terminates the session and all logical streams.
func (s *Session) Close() error {
	s.fail(ErrClosed)
	return nil
}

func (s *Session) readLoop() {
	for {
		var header [headerSize]byte
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.fail(fmt.Errorf("mux: read header: %w", err))
			return
		}
		if header[0] != protocolVersion {
			s.fail(fmt.Errorf("%w: version %d", ErrProtocol, header[0]))
			return
		}
		typ := header[1]
		id := binary.BigEndian.Uint32(header[2:6])
		length := int(binary.BigEndian.Uint16(header[6:]))
		if id == 0 || length > s.cfg.maxFramePayload {
			s.fail(fmt.Errorf("%w: stream %d length %d", ErrProtocol, id, length))
			return
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(s.conn, payload); err != nil {
			s.fail(fmt.Errorf("mux: read frame %d: %w", id, err))
			return
		}
		switch typ {
		case frameOpen:
			if length != 0 || !s.acceptRemoteID(id) {
				s.fail(fmt.Errorf("%w: invalid OPEN stream %d", ErrProtocol, id))
				return
			}
		case frameData:
			if !s.deliverData(id, payload) {
				return
			}
		case frameClose:
			if length != 0 {
				s.fail(fmt.Errorf("%w: CLOSE payload", ErrProtocol))
				return
			}
			s.deliverError(id, io.EOF)
		case frameReset:
			if length > maxResetReason {
				s.fail(fmt.Errorf("%w: RESET reason too long", ErrProtocol))
				return
			}
			reason := string(payload)
			if reason == "" {
				reason = "remote reset"
			}
			s.deliverError(id, fmt.Errorf("mux: remote reset: %s", reason))
		default:
			s.fail(fmt.Errorf("%w: frame type %d", ErrProtocol, typ))
			return
		}
	}
}

func (s *Session) acceptRemoteID(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id%2 != s.remoteParity%2 || len(s.streams) >= s.cfg.maxStreams || s.streams[id] != nil {
		return false
	}
	stream := newStream(s, id)
	s.streams[id] = stream
	select {
	case s.acceptCh <- stream:
		return true
	default:
		delete(s.streams, id)
		return false
	}
}

func (s *Session) deliverData(id uint32, payload []byte) bool {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()
	if stream == nil {
		s.fail(fmt.Errorf("%w: DATA for unknown stream %d", ErrProtocol, id))
		return false
	}
	return stream.enqueue(payload, nil)
}

func (s *Session) deliverError(id uint32, err error) {
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()
	if stream != nil {
		stream.enqueue(nil, err)
	}
}

func (s *Session) sendFrame(typ byte, id uint32, payload []byte) error {
	if len(payload) > s.cfg.maxFramePayload {
		return fmt.Errorf("mux: frame payload exceeds limit")
	}
	header := [headerSize]byte{protocolVersion, typ}
	binary.BigEndian.PutUint32(header[2:6], id)
	binary.BigEndian.PutUint16(header[6:], uint16(len(payload)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.ErrIfDone(); err != nil {
		return err
	}
	if err := writeFull(s.conn, header[:]); err != nil {
		s.fail(fmt.Errorf("mux: write header: %w", err))
		return err
	}
	if err := writeFull(s.conn, payload); err != nil {
		s.fail(fmt.Errorf("mux: write payload: %w", err))
		return err
	}
	return nil
}

func (s *Session) ErrIfDone() error {
	select {
	case <-s.done:
		return s.Err()
	default:
		return nil
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) sessionErrLocked() error {
	select {
	case <-s.done:
		return s.Err()
	default:
		return nil
	}
}

func (s *Session) fail(err error) {
	s.doneOnce.Do(func() {
		s.closeMu.Lock()
		s.err = err
		s.closeMu.Unlock()
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.mu.Unlock()
		for _, stream := range streams {
			stream.enqueue(nil, err)
		}
		close(s.acceptCh)
	})
}

type streamEvent struct {
	data []byte
	err  error
}

// Stream is a logical bidirectional net.Conn owned by a Session.
type Stream struct {
	session  *Session
	id       uint32
	events   chan streamEvent
	done     chan struct{}
	doneOnce sync.Once

	readMu      sync.Mutex
	mu          sync.Mutex
	buffer      []byte
	err         error
	readDL      time.Time
	writeDL     time.Time
	changed     chan struct{}
	closed      bool
	writeClosed bool
}

func newStream(session *Session, id uint32) *Stream {
	return &Stream{
		session: session,
		id:      id,
		events:  make(chan streamEvent, session.cfg.streamBuffer),
		done:    make(chan struct{}),
		changed: make(chan struct{}),
	}
}

func (s *Stream) enqueue(data []byte, err error) bool {
	select {
	case s.events <- streamEvent{data: append([]byte(nil), data...), err: err}:
		return true
	case <-s.done:
		return true
	case <-s.session.done:
		return true
	}
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		s.mu.Lock()
		if len(s.buffer) > 0 {
			n := copy(p, s.buffer)
			s.buffer = s.buffer[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		deadline := s.readDL
		changed := s.changed
		s.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case event := <-s.events:
			if timer != nil {
				timer.Stop()
			}
			s.mu.Lock()
			s.buffer = append(s.buffer, event.data...)
			if event.err != nil {
				s.err = event.err
			}
			s.mu.Unlock()
		case <-timeout:
			return 0, osTimeoutError{}
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-s.done:
			return 0, s.session.Err()
		}
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	if s.closed || s.writeClosed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	deadline := s.writeDL
	s.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, osTimeoutError{}
	}
	written := 0
	for written < len(p) {
		end := written + s.session.cfg.maxFramePayload
		if end > len(p) {
			end = len(p)
		}
		if err := s.session.sendFrame(frameData, s.id, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.doneOnce.Do(func() { close(s.done) })
	if err := s.CloseWrite(); err != nil && !errors.Is(err, ErrClosed) {
		return err
	}
	s.session.removeStream(s.id)
	return nil
}

// CloseWrite half-closes the local write direction while allowing the peer to
// continue sending data. It is used by bidirectional relay code.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	s.mu.Unlock()
	if err := s.session.sendFrame(frameClose, s.id, nil); err != nil && !errors.Is(err, ErrClosed) {
		return err
	}
	return nil
}

// CloseRead stops accepting local reads. The peer may continue writing until
// the session or stream is closed.
func (s *Stream) CloseRead() error {
	s.mu.Lock()
	if s.err == nil {
		s.err = ErrClosed
	}
	s.mu.Unlock()
	return nil
}

func (s *Stream) LocalAddr() net.Addr                { return s.session.conn.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr               { return s.session.conn.RemoteAddr() }
func (s *Stream) SetDeadline(t time.Time) error      { s.setDeadlines(t, t); return nil }
func (s *Stream) SetReadDeadline(t time.Time) error  { s.setDeadlines(t, time.Time{}); return nil }
func (s *Stream) SetWriteDeadline(t time.Time) error { s.setDeadlines(time.Time{}, t); return nil }

func (s *Stream) setDeadlines(read, write time.Time) {
	s.mu.Lock()
	if !read.IsZero() || write.IsZero() {
		s.readDL = read
	}
	if !write.IsZero() || read.IsZero() {
		s.writeDL = write
	}
	old := s.changed
	s.changed = make(chan struct{})
	close(old)
	s.mu.Unlock()
}

type osTimeoutError struct{}

func (osTimeoutError) Error() string   { return "i/o timeout" }
func (osTimeoutError) Timeout() bool   { return true }
func (osTimeoutError) Temporary() bool { return true }

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
