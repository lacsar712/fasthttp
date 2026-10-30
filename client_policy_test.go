package fasthttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valyala/fasthttp/fasthttputil"
)

// --- test infrastructure ---------------------------------------------------

func policyNewListener(t *testing.T, h RequestHandler) (*fasthttputil.InmemoryListener, func()) {
	t.Helper()
	ln := fasthttputil.NewInmemoryListener()
	s := &Server{
		Handler: h,
		Logger:  &testLogger{},
	}
	stop := make(chan struct{})
	go func() {
		_ = s.Serve(ln)
		close(stop)
	}()
	return ln, func() {
		_ = ln.Close()
		<-stop
	}
}

func policyDial(ln *fasthttputil.InmemoryListener) func(string) (net.Conn, error) {
	return func(string) (net.Conn, error) { return ln.Dial() }
}

func policyNewReq() *Request {
	req := AcquireRequest()
	req.SetRequestURI("http://policy-test/")
	return req
}

// startPolicyRequest runs fn on a fresh request/response pair and reports
// its error on the returned channel.
func startPolicyRequest(fn func(req *Request, resp *Response) error) chan error {
	ch := make(chan error, 1)
	go func() {
		req := policyNewReq()
		resp := AcquireResponse()
		ch <- fn(req, resp)
	}()
	return ch
}

// holdHandler blocks every request on hold until it is closed, signalling
// started for each accepted request.
func holdHandler(started chan<- struct{}, hold <-chan struct{}, body string) RequestHandler {
	var n atomic.Int32
	return func(ctx *RequestCtx) {
		n.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-hold
		_, _ = ctx.WriteString(body)
	}
}

// waitFor blocks until cond is true or the timeout fires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", msg)
}

// --- stack mechanics -------------------------------------------------------

func TestClientPolicyStackPushPop(t *testing.T) {
	req := policyNewReq()

	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("empty stack top = %v, want zero value", got)
	}

	pFailFast := ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast}
	pop1 := PushClientPolicy(req, pFailFast)
	if got := req.ClientPolicy(); got != pFailFast {
		t.Fatalf("top after push = %v, want %v", got, pFailFast)
	}

	pCap := ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeEnforceCap, MaxResponseBodySize: 42}
	pop2 := PushClientPolicy(req, pCap)
	if got := req.ClientPolicy(); got != pCap {
		t.Fatalf("nested top = %v, want %v", got, pCap)
	}

	pop2()
	if got := req.ClientPolicy(); got != pFailFast {
		t.Fatalf("top after inner pop = %v, want outer %v", got, pFailFast)
	}

	// Idempotent pop must not pop the outer frame.
	pop2()
	if got := req.ClientPolicy(); got != pFailFast {
		t.Fatalf("double inner pop corrupted stack: %v", got)
	}

	pop1()
	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("stack not empty after outer pop: %v", got)
	}

	// Reset drops a forgotten frame (pool hygiene).
	pop := PushClientPolicy(req, pCap)
	pop()
	_ = PushClientPolicy(req, pFailFast)
	req.Reset()
	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("Reset must clear the policy stack, got %v", got)
	}
}

func TestClientPolicyPopOnPanic(t *testing.T) {
	req := policyNewReq()
	frame := ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree}
	func() {
		defer func() { _ = recover() }()
		defer PushClientPolicy(req, frame)()
		panic("boom")
	}()
	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("deferred pop did not run on panic, top = %v", got)
	}
}

func TestClientPolicyContextBinding(t *testing.T) {
	req := policyNewReq()

	// No policy in context: binding is a no-op and pops cleanly.
	pop := BindClientPolicy(context.Background(), req)
	pop()
	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("BindClientPolicy without policy changed stack: %v", got)
	}

	p1 := ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast}
	p2 := ClientPolicy{DialStack: ClientPolicyDialStackForceV4}

	ctx := WithClientPolicy(context.Background(), p1)
	if got, ok := ClientPolicyFromContext(ctx); !ok || got != p1 {
		t.Fatalf("context policy = %v/%v", got, ok)
	}

	func() {
		// Nested context layer, bound to the request for one scope and
		// popped via defer like the documented exception-safe idiom.
		ctx = WithClientPolicy(ctx, p2)
		defer BindClientPolicy(ctx, req)()
		if got := req.ClientPolicy(); got != p2 {
			t.Fatalf("bound top = %v, want %v", got, p2)
		}
	}()
	if got := req.ClientPolicy(); got != (ClientPolicy{}) {
		t.Fatalf("frame leaked out of deferred scope: %v", got)
	}
}

func TestResolveClientPolicyView(t *testing.T) {
	base := ClientPolicyBaseline{
		ReadTimeout:         2 * time.Second,
		WriteTimeout:        3 * time.Second,
		MaxConnWaitTimeout:  4 * time.Second,
		DialDualStack:       false,
		MaxResponseBodySize: 100,
		StreamResponseBody:  false,
		CallTimeout:         time.Second,
	}

	// Zero frame: everything pins to the baseline.
	eff, err := ResolveClientPolicy(ClientPolicy{}, base)
	if err != nil {
		t.Fatalf("pin resolve: %v", err)
	}
	if eff.FailFastNoWait || eff.BlockUntilFree {
		t.Fatalf("pin must not wait-fail/block: %+v", eff)
	}
	if eff.ConnWaitTimeout != time.Second || eff.CallTimeout != time.Second {
		t.Fatalf("pin merge mismatch: wait=%v call=%v", eff.ConnWaitTimeout, eff.CallTimeout)
	}
	if eff.DialDualStack {
		t.Fatalf("pin dial must follow DialDualStack=false")
	}
	if eff.MaxResponseBodySize != 100 || eff.StreamResponseBody {
		t.Fatalf("pin body baseline mismatch: %+v", eff)
	}

	// fail_fast view.
	eff, err = ResolveClientPolicy(ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast}, base)
	if err != nil || !eff.FailFastNoWait {
		t.Fatalf("fail_fast view: %+v err=%v", eff, err)
	}

	// block_until_free view bounded by the call timeout, and unbounded
	// without one.
	eff, _ = ResolveClientPolicy(ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree}, base)
	if !eff.BlockUntilFree || eff.ConnWaitTimeout != time.Second {
		t.Fatalf("block view: %+v", eff)
	}
	eff, _ = ResolveClientPolicy(
		ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree},
		ClientPolicyBaseline{MaxConnWaitTimeout: 4 * time.Second},
	)
	if !eff.BlockUntilFree || eff.ConnWaitTimeout != 0 {
		t.Fatalf("unbounded block view: %+v", eff)
	}

	// deadline_merge.
	eff, _ = ResolveClientPolicy(ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeCallCapsBaseline}, base)
	if eff.CallTimeout != time.Second {
		t.Fatalf("call_caps must keep call timeout, got %v", eff.CallTimeout)
	}
	eff, _ = ResolveClientPolicy(ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeBaselineOnly}, base)
	if eff.CallTimeout != 0 {
		t.Fatalf("baseline_only must hide call timeout, got %v", eff.CallTimeout)
	}

	// dial_stack.
	eff, err = ResolveClientPolicy(
		ClientPolicy{DialStack: ClientPolicyDialStackForceDual},
		ClientPolicyBaseline{},
	)
	if err != nil || !eff.DialDualStack {
		t.Fatalf("force_dual default dialer: %+v err=%v", eff, err)
	}
	eff, err = ResolveClientPolicy(
		ClientPolicy{DialStack: ClientPolicyDialStackForceV4},
		ClientPolicyBaseline{DialDualStack: true},
	)
	if err != nil || eff.DialDualStack {
		t.Fatalf("force_v4 must override dual baseline: %+v err=%v", eff, err)
	}
	if _, err = ResolveClientPolicy(
		ClientPolicy{DialStack: ClientPolicyDialStackForceDual},
		ClientPolicyBaseline{CustomDial: true},
	); !errors.Is(err, ErrClientPolicyDialConflict) {
		t.Fatalf("force_dual + custom dial: got %v", err)
	}
	if _, err = ResolveClientPolicy(
		ClientPolicy{DialStack: ClientPolicyDialStackForceV4},
		ClientPolicyBaseline{CustomDial: true},
	); !errors.Is(err, ErrClientPolicyDialConflict) {
		t.Fatalf("force_v4 + custom dial: got %v", err)
	}

	// body_materialize.
	eff, _ = ResolveClientPolicy(
		ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeEnforceCap, MaxResponseBodySize: 7},
		ClientPolicyBaseline{MaxResponseBodySize: 100},
	)
	if eff.MaxResponseBodySize != 7 {
		t.Fatalf("frame cap must win, got %d", eff.MaxResponseBodySize)
	}
	eff, _ = ResolveClientPolicy(
		ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeEnforceCap},
		ClientPolicyBaseline{MaxResponseBodySize: 100},
	)
	if eff.MaxResponseBodySize != 100 {
		t.Fatalf("baseline cap must be merged, got %d", eff.MaxResponseBodySize)
	}
	eff, _ = ResolveClientPolicy(
		ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeStreamPrefer},
		ClientPolicyBaseline{},
	)
	if !eff.StreamResponseBody {
		t.Fatalf("stream_prefer must resolve to streaming: %+v", eff)
	}

	// Invalid enum values fail instead of being silently ignored.
	if _, err = ResolveClientPolicy(ClientPolicy{ConnWait: ClientPolicyConnWait(99)}, base); err == nil {
		t.Fatalf("invalid conn_wait must error")
	}
	if _, err = ResolveClientPolicy(ClientPolicy{DialStack: ClientPolicyDialStack(99)}, base); err == nil {
		t.Fatalf("invalid dial_stack must error")
	}
}

func TestEffectiveClientPolicyMethods(t *testing.T) {
	req := policyNewReq()
	req.SetTimeout(time.Second)
	PushClientPolicy(req, ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeBaselineOnly})

	hc := &HostClient{ReadTimeout: 5 * time.Second, MaxConnWaitTimeout: 2 * time.Second}
	eff, err := hc.EffectiveClientPolicy(req)
	if err != nil || eff.CallTimeout != 0 || eff.ReadTimeout != 5*time.Second {
		t.Fatalf("HostClient view: %+v err=%v", eff, err)
	}

	c := &Client{ReadTimeout: 5 * time.Second, MaxConnWaitTimeout: 2 * time.Second}
	eff, err = c.EffectiveClientPolicy(req)
	if err != nil || eff.CallTimeout != 0 || eff.ReadTimeout != 5*time.Second {
		t.Fatalf("Client view: %+v err=%v", eff, err)
	}

	pc := &PipelineClient{ReadTimeout: 7 * time.Second}
	eff, err = pc.EffectiveClientPolicy(req, 500*time.Millisecond)
	if err != nil || eff.CallTimeout != 0 || eff.ReadTimeout != 7*time.Second {
		t.Fatalf("PipelineClient view: %+v err=%v", eff, err)
	}
}

// --- HostClient conn_wait --------------------------------------------------

func TestHostClientPolicyConnWaitFailFast(t *testing.T) {
	for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
		t.Run(exit, func(t *testing.T) {
			started := make(chan struct{}, 4)
			hold := make(chan struct{})
			ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))
			defer cleanup()

			c := &HostClient{
				Addr:               "policy-test",
				Dial:               policyDial(ln),
				MaxConns:           1,
				MaxConnWaitTimeout: 30 * time.Second,
			}

			first := startPolicyRequest(func(req *Request, resp *Response) error {
				return c.Do(req, resp)
			})
			<-started

			req := policyNewReq()
			resp := AcquireResponse()
			pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast})

			begin := time.Now()
			var callErr error
			switch exit {
			case "Do":
				callErr = c.Do(req, resp)
			case "DoTimeout":
				callErr = c.DoTimeout(req, resp, 10*time.Second)
			case "DoDeadline":
				callErr = c.DoDeadline(req, resp, time.Now().Add(10*time.Second))
			}
			elapsed := time.Since(begin)
			pop()

			if !errors.Is(callErr, ErrNoFreeConns) {
				t.Fatalf("exit %s: %v, want ErrNoFreeConns", exit, callErr)
			}
			if elapsed > 2*time.Second {
				t.Fatalf("exit %s: fail_fast parked for %v", exit, elapsed)
			}

			close(hold)
			if err := <-first; err != nil {
				t.Fatalf("first request: %v", err)
			}
		})
	}
}

func TestHostClientPolicyConnWaitBlockUntilFree(t *testing.T) {
	started := make(chan struct{}, 4)
	hold := make(chan struct{})
	ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))
	defer cleanup()

	// Pin with MaxConnWaitTimeout == 0 returns ErrNoFreeConns immediately;
	// block_until_free must instead wait for the held connection.
	c := &HostClient{
		Addr:     "policy-test",
		Dial:     policyDial(ln),
		MaxConns: 1,
	}

	first := startPolicyRequest(func(req *Request, resp *Response) error {
		return c.Do(req, resp)
	})
	<-started

	done := make(chan error, 1)
	go func() {
		req := policyNewReq()
		resp := AcquireResponse()
		pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree})
		defer pop()
		done <- c.Do(req, resp)
	}()

	// The waiter must not return while the connection is held.
	select {
	case err := <-done:
		t.Fatalf("block waiter returned early: %v", err)
	case <-time.After(testTimeout(80 * time.Millisecond)):
	}

	close(hold)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("block waiter: %v", err)
		}
	case <-time.After(testTimeout(5 * time.Second)):
		t.Fatalf("block waiter did not complete after the conn freed")
	}
	if err := <-first; err != nil {
		t.Fatalf("first request: %v", err)
	}
}

func TestHostClientPolicyConnWaitBlockCallTimeout(t *testing.T) {
	started := make(chan struct{}, 4)
	hold := make(chan struct{})
	ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))
	defer cleanup()

	c := &HostClient{
		Addr:     "policy-test",
		Dial:     policyDial(ln),
		MaxConns: 1,
	}

	first := startPolicyRequest(func(req *Request, resp *Response) error {
		return c.Do(req, resp)
	})
	<-started

	req := policyNewReq()
	resp := AcquireResponse()
	pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree})
	defer pop()

	begin := time.Now()
	err := c.DoTimeout(req, resp, testTimeout(60*time.Millisecond))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("block + short call timeout: %v, want ErrTimeout", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("block waiter did not bound by call timeout: %v", d)
	}

	close(hold)
	if err := <-first; err != nil {
		t.Fatalf("first request: %v", err)
	}
}

func TestHostClientPolicyPinWaitsWhenFramePinned(t *testing.T) {
	started := make(chan struct{}, 4)
	hold := make(chan struct{})
	ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))
	defer cleanup()

	c := &HostClient{
		Addr:               "policy-test",
		Dial:               policyDial(ln),
		MaxConns:           1,
		MaxConnWaitTimeout: testTimeout(120 * time.Millisecond),
	}

	first := startPolicyRequest(func(req *Request, resp *Response) error {
		return c.Do(req, resp)
	})
	<-started

	// An explicit all-pin frame must behave like no frame: it parks for the
	// baseline wait and then gets ErrNoFreeConns.
	req := policyNewReq()
	defer PushClientPolicy(req, ClientPolicy{})()
	begin := time.Now()
	err := c.Do(req, AcquireResponse())
	elapsed := time.Since(begin)
	close(hold)

	if !errors.Is(err, ErrNoFreeConns) {
		t.Fatalf("pin frame: %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("pin frame did not wait: %v", elapsed)
	}
	if err := <-first; err != nil {
		t.Fatalf("first request: %v", err)
	}
}

// --- HostClient deadline_merge ---------------------------------------------

func TestHostClientPolicyDeadlineBaselineOnly(t *testing.T) {
	slow := testTimeout(150 * time.Millisecond)
	ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
		time.Sleep(slow)
		_, _ = ctx.WriteString("late")
	})
	defer cleanup()

	c := &HostClient{
		Addr:        "policy-test",
		Dial:        policyDial(ln),
		ReadTimeout: 10 * time.Second,
	}

	// Pin: the short call timeout wins over the baseline.
	resp := AcquireResponse()
	if err := c.DoTimeout(policyNewReq(), resp, 60*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("pin DoTimeout: %v, want ErrTimeout", err)
	}

	// baseline_only: the call timeout is ignored and the baseline governs.
	for _, exit := range []string{"DoTimeout", "DoDeadline"} {
		req := policyNewReq()
		resp := AcquireResponse()
		pop := PushClientPolicy(req, ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeBaselineOnly})
		var err error
		if exit == "DoTimeout" {
			err = c.DoTimeout(req, resp, 60*time.Millisecond)
		} else {
			err = c.DoDeadline(req, resp, time.Now().Add(60*time.Millisecond))
		}
		pop()
		if err != nil {
			t.Fatalf("%s baseline_only: %v, want success on the baseline timeout", exit, err)
		}
		if string(resp.Body()) != "late" {
			t.Fatalf("%s body %q", exit, resp.Body())
		}
	}
}

// silentTCPListener accepts connections, reads the ClientHello and then
// stays silent forever, so a TLS handshake blocks until its deadline.
func silentTCPListener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 1024)
				// Keep reading (and never send a ServerHello) until the
				// client closes at its handshake deadline.
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func TestHostClientPolicyDeadlineCallCapsTLSHandshake(t *testing.T) {
	// A TCP peer that accepts but never completes the TLS handshake.
	addr, cleanup := silentTCPListener(t)
	defer cleanup()

	newClient := func() *HostClient {
		return &HostClient{
			Addr:         addr,
			IsTLS:        true,
			TLSConfig:    &tls.Config{InsecureSkipVerify: true},
			WriteTimeout: 1500 * time.Millisecond,
		}
	}

	// call_caps_baseline: the 300ms call timeout must cap the TLS handshake
	// that the baseline WriteTimeout would otherwise allow for 1.5s.
	c := newClient()
	req := policyNewReq()
	req.SetRequestURI("https://" + addr + "/")
	pop := PushClientPolicy(req, ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeCallCapsBaseline})
	begin := time.Now()
	err := c.DoTimeout(req, AcquireResponse(), 300*time.Millisecond)
	capped := time.Since(begin)
	pop()
	if err == nil || !errors.Is(err, ErrTLSHandshakeTimeout) {
		t.Fatalf("call_caps handshake: %v, want ErrTLSHandshakeTimeout", err)
	}
	if capped > 1200*time.Millisecond {
		t.Fatalf("call timeout did not cap the handshake: %v", capped)
	}

	// Pin: the baseline WriteTimeout relaxes the handshake well past the
	// nominal call timeout (the blocking handshake cannot be interrupted by
	// the retry loop's remaining-time check).
	c = newClient()
	pinReq := policyNewReq()
	pinReq.SetRequestURI("https://" + addr + "/")
	begin = time.Now()
	_ = c.DoTimeout(pinReq, AcquireResponse(), 300*time.Millisecond)
	pinned := time.Since(begin)
	if pinned < 1100*time.Millisecond {
		t.Fatalf("pin handshake returned too early (%v); baseline should govern", pinned)
	}
}

// --- HostClient dial_stack -------------------------------------------------

func TestHostClientPolicyDialConflict(t *testing.T) {
	ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
		_, _ = ctx.WriteString("ok")
	})
	defer cleanup()

	for _, custom := range []string{"Dial", "DialTimeout"} {
		t.Run(custom, func(t *testing.T) {
			c := &HostClient{Addr: "policy-test", IsTLS: false}
			if custom == "Dial" {
				c.Dial = policyDial(ln)
			} else {
				c.DialTimeout = func(string, time.Duration) (net.Conn, error) { return ln.Dial() }
			}

			for _, mode := range []ClientPolicyDialStack{ClientPolicyDialStackForceDual, ClientPolicyDialStackForceV4} {
				for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
					req := policyNewReq()
					pop := PushClientPolicy(req, ClientPolicy{DialStack: mode})
					var err error
					switch exit {
					case "Do":
						err = c.Do(req, AcquireResponse())
					case "DoTimeout":
						err = c.DoTimeout(req, AcquireResponse(), time.Second)
					case "DoDeadline":
						err = c.DoDeadline(req, AcquireResponse(), time.Now().Add(time.Second))
					}
					pop()
					if !errors.Is(err, ErrClientPolicyDialConflict) {
						t.Fatalf("%s/%s/%s: %v", custom, modeName(mode), exit, err)
					}
				}
			}
		})
	}
}

func modeName(m ClientPolicyDialStack) string {
	switch m {
	case ClientPolicyDialStackForceDual:
		return "force_dual"
	case ClientPolicyDialStackForceV4:
		return "force_v4"
	default:
		return "pin"
	}
}

func TestHostClientPolicyDialDefaultStack(t *testing.T) {
	// Real TCP loopback listener so the default dialer runs (no custom Dial).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen: %v", err)
	}
	s := &Server{
		Handler: func(ctx *RequestCtx) { _, _ = ctx.WriteString("ok") },
		Logger:  &testLogger{},
	}
	stop := make(chan struct{})
	go func() { _ = s.Serve(ln); close(stop) }()
	defer func() { _ = ln.Close(); <-stop }()

	for _, mode := range []ClientPolicyDialStack{ClientPolicyDialStackForceDual, ClientPolicyDialStackForceV4} {
		c := &HostClient{Addr: ln.Addr().String(), DialDualStack: mode == ClientPolicyDialStackForceV4}
		req := policyNewReq()
		req.SetRequestURI("http://" + ln.Addr().String() + "/")
		pop := PushClientPolicy(req, ClientPolicy{DialStack: mode})
		resp := AcquireResponse()
		err := c.DoTimeout(req, resp, 3*time.Second)
		pop()
		if err != nil {
			t.Fatalf("%s default dial: %v", modeName(mode), err)
		}
		if string(resp.Body()) != "ok" {
			t.Fatalf("%s body %q", modeName(mode), resp.Body())
		}
	}
}

// --- HostClient body_materialize -------------------------------------------

func TestHostClientPolicyBodyEnforceCap(t *testing.T) {
	ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
		_, _ = ctx.Write(make([]byte, 100))
	})
	defer cleanup()

	c := &HostClient{
		Addr: "policy-test",
		Dial: policyDial(ln),
		// Baseline is uncapped; the frame supplies the cap.
	}

	// Uncapped pin baseline keeps delivering the body.
	resp := AcquireResponse()
	if err := c.Do(policyNewReq(), resp); err != nil {
		t.Fatalf("pin baseline: %v", err)
	}
	if len(resp.Body()) != 100 {
		t.Fatalf("pin body len %d", len(resp.Body()))
	}

	// enforce_cap with a frame cap smaller than the body fails testably.
	for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
		req := policyNewReq()
		pop := PushClientPolicy(req, ClientPolicy{
			BodyMaterialize:     ClientPolicyBodyMaterializeEnforceCap,
			MaxResponseBodySize: 10,
		})
		var err error
		switch exit {
		case "Do":
			err = c.Do(req, AcquireResponse())
		case "DoTimeout":
			err = c.DoTimeout(req, AcquireResponse(), 3*time.Second)
		case "DoDeadline":
			err = c.DoDeadline(req, AcquireResponse(), time.Now().Add(3*time.Second))
		}
		pop()
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("%s enforce_cap: %v, want ErrBodyTooLarge", exit, err)
		}
	}

	// enforce_cap without any positive merged cap must fail explicitly
	// instead of buffering unbounded.
	req := policyNewReq()
	pop := PushClientPolicy(req, ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeEnforceCap})
	if err := c.Do(req, AcquireResponse()); !errors.Is(err, ErrClientPolicyBodyLimit) {
		t.Fatalf("enforce_cap without cap: %v, want ErrClientPolicyBodyLimit", err)
	}
	pop()

	// Flat fields must remain exactly as configured.
	if c.MaxResponseBodySize != 0 || c.StreamResponseBody {
		t.Fatalf("client flat fields mutated: %+v", c)
	}
}

func TestHostClientPolicyBodyStreamPrefer(t *testing.T) {
	ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
		_, _ = ctx.WriteString("streamed-body")
	})
	defer cleanup()

	c := &HostClient{
		Addr:                "policy-test",
		Dial:                policyDial(ln),
		StreamResponseBody:  false,
		MaxResponseBodySize: 0,
	}

	// Pin baseline buffers the body.
	buffered := AcquireResponse()
	if err := c.Do(policyNewReq(), buffered); err != nil {
		t.Fatalf("pin Do: %v", err)
	}
	if buffered.IsBodyStream() {
		t.Fatalf("pin baseline must buffer")
	}

	// stream_prefer forces the streaming path for the frame only.
	req := policyNewReq()
	pop := PushClientPolicy(req, ClientPolicy{BodyMaterialize: ClientPolicyBodyMaterializeStreamPrefer})
	resp := AcquireResponse()
	if err := c.Do(req, resp); err != nil {
		t.Fatalf("stream_prefer Do: %v", err)
	}
	pop()
	if !resp.IsBodyStream() {
		t.Fatalf("stream_prefer must expose BodyStream")
	}
	body, err := io.ReadAll(resp.BodyStream())
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if err := resp.CloseBodyStream(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if string(body) != "streamed-body" {
		t.Fatalf("streamed body %q", body)
	}

	// After pop, buffering is back and fields are untouched.
	again := AcquireResponse()
	if err := c.Do(policyNewReq(), again); err != nil {
		t.Fatalf("post-pop Do: %v", err)
	}
	if again.IsBodyStream() || c.StreamResponseBody {
		t.Fatalf("stream preference leaked past pop")
	}
}

// --- Client exits -----------------------------------------------------------

func TestClientPolicyReadsAtClientExits(t *testing.T) {
	call := func(c *Client, exit string, p ClientPolicy) error {
		req := policyNewReq()
		req.Header.SetHost("policy-test")
		pop := PushClientPolicy(req, p)
		defer pop()
		resp := AcquireResponse()
		switch exit {
		case "Do":
			return c.Do(req, resp)
		case "DoTimeout":
			return c.DoTimeout(req, resp, 10*time.Second)
		case "DoDeadline":
			return c.DoDeadline(req, resp, time.Now().Add(10*time.Second))
		}
		panic("bad exit")
	}

	// fail_fast must be honored from all three Client exits. A fresh client
	// (and held connection) per round keeps each round independent.
	for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
		started := make(chan struct{}, 4)
		hold := make(chan struct{})
		ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))

		c := &Client{
			Name:               "policy-client-test",
			Dial:               policyDial(ln),
			MaxConnsPerHost:    1,
			MaxConnWaitTimeout: 30 * time.Second,
		}

		first := startPolicyRequest(func(req *Request, resp *Response) error {
			req.Header.SetHost("policy-test")
			return c.Do(req, resp)
		})
		<-started
		begin := time.Now()
		err := call(c, exit, ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast})
		if !errors.Is(err, ErrNoFreeConns) {
			cleanup()
			t.Fatalf("Client.%s fail_fast: %v", exit, err)
		}
		if time.Since(begin) > 2*time.Second {
			t.Fatalf("Client.%s parked despite fail_fast", exit)
		}
		close(hold)
		if err := <-first; err != nil {
			t.Fatalf("Client.%s first: %v", exit, err)
		}
		cleanup()
	}

	// force_dual against the custom Dial fails explicitly from all exits.
	{
		ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
			_, _ = ctx.WriteString("ok")
		})
		defer cleanup()
		c := &Client{Name: "policy-client-dial", Dial: policyDial(ln)}
		for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
			if err := call(c, exit, ClientPolicy{DialStack: ClientPolicyDialStackForceDual}); !errors.Is(
				err, ErrClientPolicyDialConflict,
			) {
				t.Fatalf("Client.%s force_dual: %v", exit, err)
			}
		}
	}

	// deadline_merge baseline_only from Client.DoTimeout: the short call
	// timeout is ignored and the Client ReadTimeout baseline governs.
	lateLn, lateCleanup := policyNewListener(t, func(ctx *RequestCtx) {
		time.Sleep(testTimeout(150 * time.Millisecond))
		_, _ = ctx.WriteString("late")
	})
	defer lateCleanup()
	lateClient := &Client{
		Name:        "policy-client-late",
		Dial:        policyDial(lateLn),
		ReadTimeout: 10 * time.Second,
	}
	{
		req := policyNewReq()
		req.Header.SetHost("policy-test")
		pop := PushClientPolicy(req, ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeBaselineOnly})
		resp := AcquireResponse()
		if err := lateClient.DoTimeout(req, resp, 50*time.Millisecond); err != nil {
			t.Fatalf("Client.DoTimeout baseline_only: %v", err)
		}
		pop()
		if string(resp.Body()) != "late" {
			t.Fatalf("baseline_only body %q", resp.Body())
		}
	}

	// body cap enforced from Client.Do.
	bodyLn, bodyCleanup := policyNewListener(t, func(ctx *RequestCtx) {
		_, _ = ctx.Write(make([]byte, 50))
	})
	defer bodyCleanup()
	bodyClient := &Client{Name: "policy-client-body", Dial: policyDial(bodyLn)}
	req := policyNewReq()
	req.Header.SetHost("policy-test")
	defer PushClientPolicy(req, ClientPolicy{
		BodyMaterialize:     ClientPolicyBodyMaterializeEnforceCap,
		MaxResponseBodySize: 5,
	})()
	if err := bodyClient.Do(req, AcquireResponse()); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("Client.Do enforce_cap: %v", err)
	}
}

// --- PipelineClient exits ---------------------------------------------------

func newPolicyPipelineClient(t *testing.T, ln *fasthttputil.InmemoryListener) *PipelineClient {
	t.Helper()
	return &PipelineClient{
		Addr:               "policy-test",
		Dial:               policyDial(ln),
		MaxConns:           1,
		MaxPendingRequests: 1,
		ReadTimeout:        10 * time.Second,
		Logger:             &testLogger{},
	}
}

const pipelineFillers = 4

// saturatePipeline parks requests on the single pipeline connection until
// both the response and pending channels are full and the writer holds one
// more request in flight, which is the state where no further call can be
// admitted. Fillers use block_until_free, so they never substitute another
// request while parking. The returned hold releases the server-side
// handler; the returned channel receives every filler result.
func saturatePipeline(t *testing.T, pc *PipelineClient, hold <-chan struct{}) chan error {
	t.Helper()
	errs := make(chan error, pipelineFillers)
	for range pipelineFillers {
		go func() {
			req := policyNewReq()
			pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree})
			defer pop()
			errs <- pc.Do(req, AcquireResponse())
		}()
	}

	waitFor(t, testTimeout(3*time.Second), func() bool {
		cc := pc.getConnClient()
		cc.chLock.Lock()
		chs := cc.chs
		cc.chLock.Unlock()
		if chs == nil {
			return false
		}
		// One work with the reader, one with the writer, one parked in chW.
		return len(chs.chR) == cap(chs.chR) && len(chs.chW) == cap(chs.chW)
	}, "pipeline saturated")
	return errs
}

func drainPipelineFillers(t *testing.T, errs chan error, n int) {
	t.Helper()
	for range n {
		select {
		case <-errs:
		case <-time.After(testTimeout(10 * time.Second)):
			t.Fatal("pipeline filler never finished")
		}
	}
}

func TestPipelineClientPolicyConnWait(t *testing.T) {
	newLn := func(t *testing.T, hold <-chan struct{}) (*fasthttputil.InmemoryListener, func()) {
		started := make(chan struct{}, pipelineFillers+4)
		return policyNewListener(t, holdHandler(started, hold, "x"))
	}

	// fail_fast from Do, DoTimeout and DoDeadline: no queueing, no
	// substitution, immediate ErrNoFreeConns.
	for _, exit := range []string{"Do", "DoTimeout", "DoDeadline"} {
		hold := make(chan struct{})
		ln, cleanup := newLn(t, hold)
		pc := newPolicyPipelineClient(t, ln)
		errs := saturatePipeline(t, pc, hold)

		req := policyNewReq()
		pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast})
		begin := time.Now()
		var err error
		switch exit {
		case "Do":
			err = pc.Do(req, AcquireResponse())
		case "DoTimeout":
			err = pc.DoTimeout(req, AcquireResponse(), 10*time.Second)
		case "DoDeadline":
			err = pc.DoDeadline(req, AcquireResponse(), time.Now().Add(10*time.Second))
		}
		elapsed := time.Since(begin)
		pop()
		if !errors.Is(err, ErrNoFreeConns) {
			t.Fatalf("PipelineClient.%s fail_fast: %v", exit, err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("PipelineClient.%s fail_fast parked for %v", exit, elapsed)
		}
		close(hold)
		drainPipelineFillers(t, errs, pipelineFillers)
		cleanup()
	}

	// block_until_free: the extra call waits for a slot and succeeds without
	// displacing any in-flight request.
	hold := make(chan struct{})
	ln, cleanup := newLn(t, hold)
	pc := newPolicyPipelineClient(t, ln)
	errs := saturatePipeline(t, pc, hold)
	blocked := make(chan error, 1)
	go func() {
		req := policyNewReq()
		pop := PushClientPolicy(req, ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree})
		defer pop()
		blocked <- pc.Do(req, AcquireResponse())
	}()
	select {
	case err := <-blocked:
		t.Fatalf("block returned before a slot freed: %v", err)
	case <-time.After(testTimeout(40 * time.Millisecond)):
	}
	close(hold)
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("block result: %v", err)
		}
	case <-time.After(testTimeout(10 * time.Second)):
		t.Fatalf("block did not complete after slots freed")
	}
	for range pipelineFillers {
		if err := <-errs; err != nil {
			t.Fatalf("in-flight requests must not be evicted under block: %v", err)
		}
	}
	cleanup()
}

// TestPipelineConnWaitEnqueuePolicy drives the pending/connection-admission
// equivalent path directly, without depending on network timing.
func TestPipelineConnWaitEnqueuePolicy(t *testing.T) {
	mkWork := func() *pipelineWork {
		return &pipelineWork{done: make(chan struct{}, 1)}
	}
	mkChs := func(old *pipelineWork) (*pipelineConnClient, *pipelineConnChannels) {
		c := &pipelineConnClient{}
		chs := &pipelineConnChannels{
			chW: make(chan *pipelineWork, 1),
			chR: make(chan *pipelineWork, 1),
		}
		if old != nil {
			chs.chW <- old
		}
		return c, chs
	}

	// Pin plain Do: substitutes the oldest work and admits the new one.
	old := mkWork()
	c, chs := mkChs(old)
	w := mkWork()
	if err := c.enqueuePipelineWork(chs, w, nil); err != nil {
		t.Fatalf("pin enqueue: %v", err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("pin must signal the substituted work")
	}
	if old.err != ErrPipelineOverflow {
		t.Fatalf("substituted work err: %v", old.err)
	}
	if got := <-chs.chW; got != w {
		t.Fatal("new work must be admitted under pin")
	}

	// fail_fast: rejects without touching the queued work.
	old = mkWork()
	c, chs = mkChs(old)
	w = mkWork()
	eff := &resolvedPipelinePolicy{connWaitFailFast: true}
	if err := c.enqueuePipelineWork(chs, w, eff); !errors.Is(err, ErrNoFreeConns) {
		t.Fatalf("fail_fast enqueue: %v", err)
	}
	select {
	case <-old.done:
		t.Fatal("fail_fast must not substitute the queued work")
	default:
	}
	if got := <-chs.chW; got != old {
		t.Fatal("fail_fast must leave the queued work in place")
	}

	// block_until_free with an armed timer: waits and returns ErrTimeout
	// when the timer fires, without substituting.
	old = mkWork()
	c, chs = mkChs(old)
	w = mkWork()
	w.t = time.NewTimer(50 * time.Millisecond)
	w.timerArmed = true
	eff = &resolvedPipelinePolicy{connWaitBlock: true}
	if err := c.enqueuePipelineWork(chs, w, eff); !errors.Is(err, ErrTimeout) {
		t.Fatalf("block armed enqueue: %v", err)
	}
	if got := <-chs.chW; got != old {
		t.Fatal("block armed must not substitute")
	}

	// block_until_free unarmed: parks until a slot frees, then is admitted.
	old = mkWork()
	c, chs = mkChs(old)
	w = mkWork()
	eff = &resolvedPipelinePolicy{connWaitBlock: true}
	gotErr := make(chan error, 1)
	go func() { gotErr <- c.enqueuePipelineWork(chs, w, eff) }()
	select {
	case err := <-gotErr:
		t.Fatalf("unarmed block returned before a slot freed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	<-chs.chW // free the slot
	select {
	case err := <-gotErr:
		if err != nil {
			t.Fatalf("unarmed block after free slot: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unarmed block was not admitted")
	}
	if got := <-chs.chW; got != w {
		t.Fatal("unarmed block must admit the waiting work")
	}

	// A pin call with an armed timer waits too (no substitution).
	old = mkWork()
	c, chs = mkChs(old)
	w = mkWork()
	w.t = time.NewTimer(time.Minute)
	w.timerArmed = true
	gotErr = make(chan error, 1)
	go func() { gotErr <- c.enqueuePipelineWork(chs, w, nil) }()
	select {
	case <-gotErr:
		t.Fatal("armed pin must wait for the timer, not substitute")
	case <-time.After(50 * time.Millisecond):
	}
	<-chs.chW
	select {
	case err := <-gotErr:
		if err != nil {
			t.Fatalf("armed pin after free slot: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("armed pin was not admitted")
	}
}

func TestPipelineClientPolicyDeadlineBaselineOnly(t *testing.T) {
	slow := testTimeout(150 * time.Millisecond)
	ln, cleanup := policyNewListener(t, func(ctx *RequestCtx) {
		time.Sleep(slow)
		_, _ = ctx.WriteString("late")
	})
	defer cleanup()
	pc := newPolicyPipelineClient(t, ln)

	// Pin: short DoTimeout/DoDeadline expire.
	if err := pc.DoTimeout(policyNewReq(), AcquireResponse(), 50*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("pin DoTimeout: %v", err)
	}
	if err := pc.DoDeadline(policyNewReq(), AcquireResponse(), time.Now().Add(50*time.Millisecond)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("pin DoDeadline: %v", err)
	}

	// baseline_only: the frame ignores the tightening and succeeds under the
	// worker baseline ReadTimeout.
	for _, exit := range []string{"DoTimeout", "DoDeadline"} {
		req := policyNewReq()
		resp := AcquireResponse()
		pop := PushClientPolicy(req, ClientPolicy{DeadlineMerge: ClientPolicyDeadlineMergeBaselineOnly})
		var err error
		if exit == "DoTimeout" {
			err = pc.DoTimeout(req, resp, 50*time.Millisecond)
		} else {
			err = pc.DoDeadline(req, resp, time.Now().Add(50*time.Millisecond))
		}
		pop()
		if err != nil {
			t.Fatalf("%s baseline_only: %v", exit, err)
		}
		if string(resp.Body()) != "late" {
			t.Fatalf("%s body %q", exit, resp.Body())
		}
	}
}

func TestPipelineClientPolicyDeadlineCallCaps(t *testing.T) {
	// blockedFirstHandler answers every request immediately except the
	// first one, which blocks until the test releases it.
	blockedFirstHandler := func() RequestHandler {
		var n atomic.Int32
		hold := make(chan struct{})
		return func(ctx *RequestCtx) {
			if n.Add(1) == 1 {
				<-hold
			}
			_, _ = ctx.WriteString("ok")
		}
	}

	for _, tc := range []struct {
		name           string
		mode           ClientPolicyDeadlineMerge
		secondWantErr  bool
		secondDeadline time.Duration
	}{
		// call_caps_baseline: the capped reader breaks the stalled pipeline
		// at the call deadline, a new connection is established and the
		// second request succeeds.
		{name: "call_caps_baseline", mode: ClientPolicyDeadlineMergeCallCapsBaseline, secondWantErr: false, secondDeadline: 6 * time.Second},
		// Pin: the reader stays blocked on the baseline ReadTimeout, so the
		// second response is stuck behind the first one and the second call
		// times out.
		{name: "pin", mode: ClientPolicyDeadlineMergePin, secondWantErr: true, secondDeadline: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, cleanup := policyNewListener(t, blockedFirstHandler())
			defer cleanup()

			pc := &PipelineClient{
				Addr:               "policy-test",
				Dial:               policyDial(ln),
				MaxConns:           1,
				MaxPendingRequests: 4,
				ReadTimeout:        10 * time.Second,
				Logger:             &testLogger{},
			}

			req := policyNewReq()
			pop := PushClientPolicy(req, ClientPolicy{DeadlineMerge: tc.mode})
			begin := time.Now()
			err := pc.DoTimeout(req, AcquireResponse(), 200*time.Millisecond)
			pop()
			if !errors.Is(err, ErrTimeout) {
				t.Fatalf("%s DoTimeout: %v", tc.name, err)
			}
			if d := time.Since(begin); d > 2*time.Second {
				t.Fatalf("%s first call returned late: %v", tc.name, d)
			}

			// Second call without a frame. Under call_caps the capped reader
			// tore down the stalled pipeline and the client reconnects; a
			// request caught in that restart window gets
			// errPipelineConnStopped, which is transient, so retry it. Under
			// pin the old connection stays parked behind the stalled first
			// response and the second call times out.
			secondBegin := time.Now()
			secondDeadline := time.Now().Add(tc.secondDeadline)
			for {
				err = pc.DoDeadline(policyNewReq(), AcquireResponse(), secondDeadline)
				if !tc.secondWantErr && errors.Is(err, errPipelineConnStopped) &&
					time.Now().Before(secondDeadline) {
					continue
				}
				break
			}
			secondElapsed := time.Since(secondBegin)
			if tc.secondWantErr {
				if !errors.Is(err, ErrTimeout) {
					t.Fatalf("%s second call: %v, want ErrTimeout", tc.name, err)
				}
				if secondElapsed < tc.secondDeadline-time.Second {
					t.Fatalf("%s second call returned too early: %v", tc.name, secondElapsed)
				}
			} else {
				if err != nil {
					t.Fatalf("%s second call: %v, want success on a fresh connection", tc.name, err)
				}
				if secondElapsed > tc.secondDeadline {
					t.Fatalf("%s second call took %v", tc.name, secondElapsed)
				}
			}
		})
	}
}

// --- concurrency isolation --------------------------------------------------

func TestClientPolicyConcurrentStacks(t *testing.T) {
	started := make(chan struct{}, 8)
	hold := make(chan struct{})
	ln, cleanup := policyNewListener(t, holdHandler(started, hold, "held"))
	defer cleanup()

	c := &HostClient{
		Addr:     "policy-test",
		Dial:     policyDial(ln),
		MaxConns: 1,
		// Pin baseline fails immediately; only the block frame may wait.
	}

	holder := startPolicyRequest(func(req *Request, resp *Response) error {
		return c.Do(req, resp)
	})
	<-started

	// Goroutine B: block_until_free frame on a different request. It stays
	// parked until hold is released, so it is not part of the WaitGroup.
	blockDone := make(chan error, 1)
	go func() {
		reqB := policyNewReq()
		pop := PushClientPolicy(reqB, ClientPolicy{ConnWait: ClientPolicyConnWaitBlockUntilFree})
		defer pop()
		if got := reqB.ClientPolicy().ConnWait; got != ClientPolicyConnWaitBlockUntilFree {
			t.Errorf("B sees policy %v", got)
		}
		blockDone <- c.Do(reqB, AcquireResponse())
	}()

	// Give B a moment to park, then make A fail fast on a different request.
	time.Sleep(testTimeout(30 * time.Millisecond))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqA := policyNewReq()
		pop := PushClientPolicy(reqA, ClientPolicy{ConnWait: ClientPolicyConnWaitFailFast})
		defer pop()
		if got := reqA.ClientPolicy().ConnWait; got != ClientPolicyConnWaitFailFast {
			t.Errorf("A sees policy %v", got)
		}
		if err := c.Do(reqA, AcquireResponse()); !errors.Is(err, ErrNoFreeConns) {
			t.Errorf("A: %v, want ErrNoFreeConns", err)
		}
	}()
	wg.Wait()

	select {
	case err := <-blockDone:
		t.Fatalf("block goroutine must still wait: %v", err)
	case <-time.After(testTimeout(60 * time.Millisecond)):
	}

	close(hold)
	if err := <-blockDone; err != nil {
		t.Fatalf("B after release: %v", err)
	}
	if err := <-holder; err != nil {
		t.Fatalf("holder: %v", err)
	}
}
