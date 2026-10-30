package fasthttp

import (
	"context"
	"errors"
	"strconv"
	"time"
)

// Request-scoped client policy stack.
//
// The flat fields of Client, HostClient and PipelineClient (MaxConns,
// MaxConnWaitTimeout, ReadTimeout, WriteTimeout, DialDualStack,
// MaxResponseBodySize, StreamResponseBody, the Dial callbacks, ...) describe
// process-lifetime baselines shared by every concurrent call. Temporarily
// overriding them for a single nested call means mutating the field and
// restoring it afterwards, which leaks across nested and panic/error paths
// and makes two concurrent calls step on each other.
//
// ClientPolicy frames solve this without touching any flat field. A frame is
// pushed onto the policy stack carried by a *Request, applies only to calls
// made with that request while the frame is on top, and is popped again with
// the returned pop function. The stack is mounted on the request instead of
// in a package-level singleton: requests may not be used concurrently, while
// two goroutines executing two requests (even against the same Client,
// HostClient or PipelineClient) each carry their own stack and can never see
// each other's frames.
//
// The zero value of every axis is "pin", i.e. keep the existing behavior.
// With no frame pushed (or an all-pin frame), behavior is identical to the
// flat-field configuration.

var (
	// ErrClientPolicyDialConflict is returned when a pushed ClientPolicy
	// requests force_dual or force_v4 dialing while the target
	// Client/HostClient uses a custom Dial or DialTimeout callback.
	//
	// Custom dial callbacks are opaque, so the client cannot prove which IP
	// stack they use. Instead of silently pretending the request was dialed
	// dual-stack or IPv4-only, the call fails with this error. Remove the
	// custom dialer or pin the dial_stack axis for this frame.
	ErrClientPolicyDialConflict = errors.New("fasthttp: client policy cannot force the dial IP stack because a custom Dial or DialTimeout is set")

	// ErrClientPolicyBodyLimit is returned when a pushed ClientPolicy
	// requests enforce_cap response body handling but neither the frame nor
	// the Client/HostClient baseline provides a positive
	// MaxResponseBodySize.
	//
	// Without a merged cap the body would have to be buffered unboundedly,
	// which is exactly what enforce_cap forbids. Push a frame with a positive
	// MaxResponseBodySize, configure one on the client, or combine the frame
	// with stream_prefer instead.
	ErrClientPolicyBodyLimit = errors.New("fasthttp: client policy enforces a response body cap but no positive MaxResponseBodySize is configured")
)

// ClientPolicyConnWait selects what happens when a call needs a connection
// and no idle connection and no connection capacity is available.
type ClientPolicyConnWait int

const (
	// ClientPolicyConnWaitPin keeps the baseline behavior: wait up to
	// MaxConnWaitTimeout (bounded by the call timeout) for a free connection,
	// or return ErrNoFreeConns immediately when MaxConnWaitTimeout is not set.
	ClientPolicyConnWaitPin ClientPolicyConnWait = iota

	// ClientPolicyConnWaitFailFast makes the frame return ErrNoFreeConns
	// immediately when no connection is available right now. The call is
	// never parked in the connection wait queue.
	ClientPolicyConnWaitFailFast

	// ClientPolicyConnWaitBlockUntilFree makes the frame wait until a
	// connection becomes available or until the call timeout (if any)
	// expires, ignoring MaxConnWaitTimeout. With no call timeout the wait is
	// unbounded.
	ClientPolicyConnWaitBlockUntilFree
)

// ClientPolicyDeadlineMerge selects how the timeout passed to DoTimeout or
// DoDeadline (and stored on the request) merges with the ReadTimeout and
// WriteTimeout baseline fields.
type ClientPolicyDeadlineMerge int

const (
	// ClientPolicyDeadlineMergePin keeps the existing merge: the call
	// timeout and the baseline timeouts apply together, each read/write
	// deadline being the earlier of the two.
	ClientPolicyDeadlineMergePin ClientPolicyDeadlineMerge = iota

	// ClientPolicyDeadlineMergeCallCapsBaseline makes the per-call timeout
	// or deadline the upper bound for every blocking operation of the frame,
	// including connection acquisition, dialing and the TLS handshake. A
	// larger ReadTimeout, WriteTimeout or dial baseline can never extend the
	// frame past the call deadline.
	ClientPolicyDeadlineMergeCallCapsBaseline

	// ClientPolicyDeadlineMergeBaselineOnly makes the frame ignore the
	// tightening intent of DoTimeout/DoDeadline for connection, read and
	// write deadlines; only the client baseline timeouts govern the call.
	ClientPolicyDeadlineMergeBaselineOnly
)

// ClientPolicyDialStack selects the IP stack used by the default dial path.
type ClientPolicyDialStack int

const (
	// ClientPolicyDialStackPin keeps the baseline DialDualStack field.
	ClientPolicyDialStackPin ClientPolicyDialStack = iota

	// ClientPolicyDialStackForceDual forces dual-stack (IPv4 and IPv6)
	// dialing on the default dialer for the frame. When a custom Dial or
	// DialTimeout callback is configured the call fails with
	// ErrClientPolicyDialConflict instead of pretending the callback dialed
	// dual-stack.
	ClientPolicyDialStackForceDual

	// ClientPolicyDialStackForceV4 forbids dual-stack dialing for the frame
	// and uses the IPv4-only default dial path. When a custom Dial or
	// DialTimeout callback is configured the call fails with
	// ErrClientPolicyDialConflict instead of pretending the callback dialed
	// IPv4-only.
	ClientPolicyDialStackForceV4
)

// ClientPolicyBodyMaterialize selects how the response body is materialized.
type ClientPolicyBodyMaterialize int

const (
	// ClientPolicyBodyMaterializePin keeps the baseline
	// MaxResponseBodySize and StreamResponseBody settings.
	ClientPolicyBodyMaterializePin ClientPolicyBodyMaterialize = iota

	// ClientPolicyBodyMaterializeEnforceCap requires a positive merged
	// response body cap (the frame's MaxResponseBodySize, falling back to
	// the client baseline). A body exceeding the cap fails with
	// ErrBodyTooLarge; the body is never silently buffered in full. If no
	// positive cap is configured anywhere, the call fails with
	// ErrClientPolicyBodyLimit instead of reading an unbounded body.
	ClientPolicyBodyMaterializeEnforceCap

	// ClientPolicyBodyMaterializeStreamPrefer makes the frame take the
	// streaming response path (Response.BodyStream) unless the request
	// explicitly forces body buffering. The client is not mutated to achieve
	// this.
	ClientPolicyBodyMaterializeStreamPrefer
)

// ClientPolicy is one frame of the request-scoped client policy stack.
//
// The zero value pins every axis to the client's flat-field baseline, so an
// empty frame changes nothing. Frames are pushed with PushClientPolicy and
// are effective for Client, HostClient and PipelineClient calls performed
// with the carrying request until the frame is popped.
type ClientPolicy struct {
	// ConnWait overrides the MaxConnWaitTimeout/ErrNoFreeConns baseline for
	// the frame.
	ConnWait ClientPolicyConnWait

	// DeadlineMerge overrides how DoTimeout/DoDeadline merge with the
	// ReadTimeout/WriteTimeout baseline for the frame.
	DeadlineMerge ClientPolicyDeadlineMerge

	// DialStack overrides the DialDualStack baseline for the default dial
	// path of the frame.
	DialStack ClientPolicyDialStack

	// BodyMaterialize overrides the MaxResponseBodySize/StreamResponseBody
	// baseline for the frame.
	BodyMaterialize ClientPolicyBodyMaterialize

	// MaxResponseBodySize optionally supplies the response body cap merged
	// in for BodyMaterializeEnforceCap (and consulted for
	// StreamPrefer) when the client baseline is uncapped. It is ignored on
	// the pin axes.
	MaxResponseBodySize int
}

func (p ClientPolicy) isZero() bool {
	return p == ClientPolicy{}
}

// clientPolicyFrame is a linked-list node of the stack mounted on a Request.
type clientPolicyFrame struct {
	policy ClientPolicy
	prev   *clientPolicyFrame
}

// PushClientPolicy pushes policy onto the request-scoped client policy stack
// and returns a pop function. The frame applies to every Client, HostClient
// or PipelineClient call performed with req until pop is invoked.
//
// The returned pop function is idempotent and restores the previous stack
// head, so nested frames unwind in order. Call it with defer right after
// pushing to make panic and error paths pop the frame deterministically:
//
//	pop := fasthttp.PushClientPolicy(req, fasthttp.ClientPolicy{
//	    ConnWait: fasthttp.ClientPolicyConnWaitFailFast,
//	})
//	defer pop()
//
// The stack is carried by req; concurrent calls using distinct requests
// never interfere. No flat client field is modified, so there is nothing to
// restore on MaxConns, DialDualStack or MaxResponseBodySize.
func PushClientPolicy(req *Request, policy ClientPolicy) (pop func()) {
	f := &clientPolicyFrame{
		policy: policy,
		prev:   req.policyTop,
	}
	req.policyTop = f
	popped := false
	return func() {
		if popped {
			return
		}
		popped = true
		// Only unwind when this frame is still the head. A mismatch means
		// the stack was reset meanwhile; leave the current stack alone.
		if req.policyTop == f {
			req.policyTop = f.prev
		}
	}
}

// ClientPolicy returns the policy frame currently on top of the
// request-scoped stack, or the zero value when the stack is empty.
func (req *Request) ClientPolicy() ClientPolicy {
	if req.policyTop == nil {
		return ClientPolicy{}
	}
	return req.policyTop.policy
}

type clientPolicyContextKey struct{}

// WithClientPolicy returns a copy of ctx carrying policy. The context alone
// does not affect any call; bind it to a request for the duration of a call
// scope with BindClientPolicy.
//
// Nested WithClientPolicy values layer like a stack: the latest value wins,
// and popping the binding restores the outer one.
func WithClientPolicy(ctx context.Context, policy ClientPolicy) context.Context {
	return context.WithValue(ctx, clientPolicyContextKey{}, policy)
}

// ClientPolicyFromContext returns the ClientPolicy carried by ctx and whether
// one was present.
func ClientPolicyFromContext(ctx context.Context) (ClientPolicy, bool) {
	p, ok := ctx.Value(clientPolicyContextKey{}).(ClientPolicy)
	return p, ok
}

// BindClientPolicy pushes the ClientPolicy carried by ctx (see
// WithClientPolicy) onto the request-scoped stack and returns the pop
// function. When ctx carries no policy the request is left untouched and a
// no-op pop is returned.
//
// This is the context idiom for nested business code: the policy travels
// through context.Context and is bound to a request only for an explicit
// call scope. Defer the returned function so panic and early-return paths
// still pop the frame:
//
//	defer fasthttp.BindClientPolicy(ctx, req)()
//	err := client.Do(req, resp)
func BindClientPolicy(ctx context.Context, req *Request) func() {
	p, ok := ClientPolicyFromContext(ctx)
	if !ok {
		return func() {}
	}
	return PushClientPolicy(req, p)
}

// clientPolicyBaseline are the flat HostClient/Client fields a frame merges
// with. CallTimeout is the per-call timeout carried on the request by
// DoTimeout/DoDeadline; zero means the call has no timeout.
type clientPolicyBaseline struct {
	readTimeout         time.Duration
	writeTimeout        time.Duration
	maxConnWaitTimeout  time.Duration
	dialDualStack       bool
	customDial          bool
	maxResponseBodySize int
	streamResponseBody  bool
}

// resolvedClientPolicy is the internal effective view of a frame merged with
// a client baseline. A nil pointer means "no frame, existing behavior".
type resolvedClientPolicy struct {
	// connWait
	connWaitFailFast bool
	connWaitBlock    bool

	// deadline merge
	callCapsBaseline  bool // the call timeout caps every blocking op
	ignoreCallTimeout bool // baseline_only: behave as if no call timeout was given
	callTimeout       time.Duration

	// dial stack
	dialOverride  bool
	dialDualStack bool

	// body materialization
	streamPrefer   bool
	enforceBodyCap bool
	bodyCap        int
}

func resolveClientPolicy(p ClientPolicy, b clientPolicyBaseline, callTimeout time.Duration) (*resolvedClientPolicy, error) {
	r := &resolvedClientPolicy{
		callTimeout:   callTimeout,
		dialDualStack: b.dialDualStack,
		bodyCap:       b.maxResponseBodySize,
		streamPrefer:  b.streamResponseBody,
	}

	switch p.ConnWait {
	case ClientPolicyConnWaitFailFast:
		r.connWaitFailFast = true
	case ClientPolicyConnWaitBlockUntilFree:
		r.connWaitBlock = true
	case ClientPolicyConnWaitPin:
	default:
		return nil, fmtClientPolicyInvalidValue("conn_wait", int(p.ConnWait))
	}

	switch p.DeadlineMerge {
	case ClientPolicyDeadlineMergeCallCapsBaseline:
		r.callCapsBaseline = true
	case ClientPolicyDeadlineMergeBaselineOnly:
		r.ignoreCallTimeout = true
		r.callTimeout = 0
	case ClientPolicyDeadlineMergePin:
	default:
		return nil, fmtClientPolicyInvalidValue("deadline_merge", int(p.DeadlineMerge))
	}

	switch p.DialStack {
	case ClientPolicyDialStackForceDual:
		if b.customDial {
			return nil, ErrClientPolicyDialConflict
		}
		r.dialOverride = true
		r.dialDualStack = true
	case ClientPolicyDialStackForceV4:
		if b.customDial {
			return nil, ErrClientPolicyDialConflict
		}
		r.dialOverride = true
		r.dialDualStack = false
	case ClientPolicyDialStackPin:
	default:
		return nil, fmtClientPolicyInvalidValue("dial_stack", int(p.DialStack))
	}

	switch p.BodyMaterialize {
	case ClientPolicyBodyMaterializeEnforceCap:
		r.enforceBodyCap = true
		if p.MaxResponseBodySize > 0 {
			r.bodyCap = p.MaxResponseBodySize
		}
	case ClientPolicyBodyMaterializeStreamPrefer:
		r.streamPrefer = true
		if p.MaxResponseBodySize > 0 {
			r.bodyCap = p.MaxResponseBodySize
		}
	case ClientPolicyBodyMaterializePin:
	default:
		return nil, fmtClientPolicyInvalidValue("body_materialize", int(p.BodyMaterialize))
	}

	return r, nil
}

func fmtClientPolicyInvalidValue(axis string, v int) error {
	return errors.New("fasthttp: invalid client policy value " + axis + "=" + strconv.Itoa(v))
}

// ClientPolicyBaseline is the public projection of the flat Client,
// HostClient or PipelineClient baseline fields that a ClientPolicy frame
// merges with.
type ClientPolicyBaseline struct {
	// ReadTimeout/WriteTimeout are the baseline per-operation timeouts.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// MaxConnWaitTimeout is the baseline time spent waiting for a free
	// connection.
	MaxConnWaitTimeout time.Duration

	// DialDualStack is the baseline default-dialer IP stack choice.
	DialDualStack bool

	// CustomDial reports whether a Dial or DialTimeout callback is set.
	CustomDial bool

	// MaxResponseBodySize is the baseline buffered body cap.
	MaxResponseBodySize int

	// StreamResponseBody is the baseline streaming choice.
	StreamResponseBody bool

	// CallTimeout is the timeout of the current single call
	// (DoTimeout/DoDeadline/Request.SetTimeout), zero when unset.
	CallTimeout time.Duration
}

// EffectiveClientPolicy is the effective view after merging a ClientPolicy
// frame with a client baseline.
type EffectiveClientPolicy struct {
	// ConnWait is the resolved connection-acquisition mode.
	ConnWait ClientPolicyConnWait

	// FailFastNoWait reports whether a call returns ErrNoFreeConns at once
	// instead of parking for a connection.
	FailFastNoWait bool

	// BlockUntilFree reports whether the call waits for a connection
	// independently of MaxConnWaitTimeout.
	BlockUntilFree bool

	// ConnWaitTimeout is the effective bound for waiting for a connection.
	// Zero with BlockUntilFree true means unbounded waiting. Under pin it is
	// MaxConnWaitTimeout capped by the call timeout.
	ConnWaitTimeout time.Duration

	// DeadlineMerge is the resolved merge mode.
	DeadlineMerge ClientPolicyDeadlineMerge

	// CallTimeout is the effective per-call timeout after merging. Zero
	// means the frame ignores the caller timeout (baseline_only) or none was
	// given.
	CallTimeout time.Duration

	// ReadTimeout/WriteTimeout are the effective baseline timeouts.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// DialStack is the resolved dial mode and DialDualStack its effective
	// default-dialer choice.
	DialStack     ClientPolicyDialStack
	DialDualStack bool

	// BodyMaterialize is the resolved body mode. MaxResponseBodySize is the
	// effective buffered body cap and StreamResponseBody the effective
	// streaming choice.
	BodyMaterialize     ClientPolicyBodyMaterialize
	MaxResponseBodySize int
	StreamResponseBody  bool
}

// ResolveClientPolicy returns the effective view of policy merged with base.
// It returns ErrClientPolicyDialConflict when force_dual/force_v4 meets a
// custom dialer, and mirrors every merge applied inside the client call
// paths. The read is pure: no client field is touched.
func ResolveClientPolicy(policy ClientPolicy, base ClientPolicyBaseline) (EffectiveClientPolicy, error) {
	r, err := resolveClientPolicy(policy, clientPolicyBaseline{
		readTimeout:         base.ReadTimeout,
		writeTimeout:        base.WriteTimeout,
		maxConnWaitTimeout:  base.MaxConnWaitTimeout,
		dialDualStack:       base.DialDualStack,
		customDial:          base.CustomDial,
		maxResponseBodySize: base.MaxResponseBodySize,
		streamResponseBody:  base.StreamResponseBody,
	}, base.CallTimeout)
	if err != nil {
		return EffectiveClientPolicy{}, err
	}

	eff := EffectiveClientPolicy{
		ConnWait:            policy.ConnWait,
		FailFastNoWait:      r.connWaitFailFast,
		BlockUntilFree:      r.connWaitBlock,
		DeadlineMerge:       policy.DeadlineMerge,
		CallTimeout:         r.callTimeout,
		ReadTimeout:         base.ReadTimeout,
		WriteTimeout:        base.WriteTimeout,
		DialStack:           policy.DialStack,
		DialDualStack:       r.dialDualStack,
		BodyMaterialize:     policy.BodyMaterialize,
		MaxResponseBodySize: r.bodyCap,
		StreamResponseBody:  r.streamPrefer,
	}

	switch {
	case r.connWaitBlock:
		eff.ConnWaitTimeout = r.callTimeout
	case base.MaxConnWaitTimeout > 0:
		eff.ConnWaitTimeout = base.MaxConnWaitTimeout
		if r.callTimeout > 0 && r.callTimeout < eff.ConnWaitTimeout {
			eff.ConnWaitTimeout = r.callTimeout
		}
	}
	return eff, nil
}

func (c *HostClient) hostClientPolicyBaseline(req *Request) clientPolicyBaseline {
	return clientPolicyBaseline{
		readTimeout:         c.ReadTimeout,
		writeTimeout:        c.WriteTimeout,
		maxConnWaitTimeout:  c.MaxConnWaitTimeout,
		dialDualStack:       c.DialDualStack,
		customDial:          c.Dial != nil || c.DialTimeout != nil,
		maxResponseBodySize: c.MaxResponseBodySize,
		streamResponseBody:  c.StreamResponseBody,
	}
}

// resolveRequestPolicy merges the stack top carried by req with this
// HostClient baseline. A nil result with nil error means "no frame pushed".
func (c *HostClient) resolveRequestPolicy(req *Request) (*resolvedClientPolicy, error) {
	if req.policyTop == nil {
		return nil, nil
	}
	return resolveClientPolicy(req.policyTop.policy, c.hostClientPolicyBaseline(req), req.timeout)
}

// EffectiveClientPolicy returns the effective view of the policy stack
// carried by req merged with this HostClient baseline and the request's
// current call timeout. It does not perform a request.
func (c *HostClient) EffectiveClientPolicy(req *Request) (EffectiveClientPolicy, error) {
	policy := req.ClientPolicy()
	return ResolveClientPolicy(policy, ClientPolicyBaseline{
		ReadTimeout:         c.ReadTimeout,
		WriteTimeout:        c.WriteTimeout,
		MaxConnWaitTimeout:  c.MaxConnWaitTimeout,
		DialDualStack:       c.DialDualStack,
		CustomDial:          c.Dial != nil || c.DialTimeout != nil,
		MaxResponseBodySize: c.MaxResponseBodySize,
		StreamResponseBody:  c.StreamResponseBody,
		CallTimeout:         req.timeout,
	})
}

// EffectiveClientPolicy returns the effective view of the policy stack
// carried by req merged with this Client flat-field baseline and the
// request's current call timeout. Per-host HostClients created by the Client
// copy these fields, so the Client baseline is reported even before the first
// request to a host created the HostClient. It does not perform a request.
func (c *Client) EffectiveClientPolicy(req *Request) (EffectiveClientPolicy, error) {
	policy := req.ClientPolicy()
	return ResolveClientPolicy(policy, ClientPolicyBaseline{
		ReadTimeout:         c.ReadTimeout,
		WriteTimeout:        c.WriteTimeout,
		MaxConnWaitTimeout:  c.MaxConnWaitTimeout,
		DialDualStack:       c.DialDualStack,
		CustomDial:          c.Dial != nil || c.DialTimeout != nil,
		MaxResponseBodySize: c.MaxResponseBodySize,
		StreamResponseBody:  c.StreamResponseBody,
		CallTimeout:         req.timeout,
	})
}

// EffectiveClientPolicy returns the effective view of the policy stack
// carried by req merged with this PipelineClient baseline and the given call
// timeout. Pass the DoTimeout/DoDeadline timeout (zero for a plain Do) as
// callTimeout. It does not perform a request.
func (c *PipelineClient) EffectiveClientPolicy(req *Request, callTimeout time.Duration) (EffectiveClientPolicy, error) {
	policy := req.ClientPolicy()
	return ResolveClientPolicy(policy, ClientPolicyBaseline{
		ReadTimeout:         c.ReadTimeout,
		WriteTimeout:        c.WriteTimeout,
		MaxConnWaitTimeout:  0,
		DialDualStack:       c.DialDualStack,
		CustomDial:          c.Dial != nil,
		MaxResponseBodySize: c.MaxResponseBodySize,
		StreamResponseBody:  false,
		CallTimeout:         callTimeout,
	})
}

// resolvedPipelinePolicy carries the conn_wait and deadline_merge decisions
// a PipelineClient frame took at entry into the pipelining internals. The
// pipeline worker goroutine dials and multiplexes independently of any
// request frame, so dial_stack and body_materialize are not applied there.
type resolvedPipelinePolicy struct {
	connWaitFailFast bool
	connWaitBlock    bool

	// callTimeout is the effective caller wait timeout; zero means the
	// caller does not arm a timeout (baseline_only or a plain Do).
	callTimeout time.Duration
	// capConnDeadline makes the worker cap per-request read/write deadlines
	// by the work's call deadline (call_caps_baseline).
	capConnDeadline bool
}

func (c *PipelineClient) resolveRequestPolicy(req *Request, callTimeout time.Duration) (*resolvedPipelinePolicy, error) {
	if req.policyTop == nil {
		if callTimeout <= 0 {
			return nil, nil
		}
		return &resolvedPipelinePolicy{callTimeout: callTimeout}, nil
	}
	p := req.policyTop.policy

	// Dial stack is unsupported on the pipeline worker and body
	// materialization is governed by the worker's buffered body model, so
	// only conn_wait and deadline_merge are validated here.
	switch p.ConnWait {
	case ClientPolicyConnWaitPin, ClientPolicyConnWaitFailFast, ClientPolicyConnWaitBlockUntilFree:
	default:
		return nil, fmtClientPolicyInvalidValue("conn_wait", int(p.ConnWait))
	}
	switch p.DeadlineMerge {
	case ClientPolicyDeadlineMergePin, ClientPolicyDeadlineMergeCallCapsBaseline, ClientPolicyDeadlineMergeBaselineOnly:
	default:
		return nil, fmtClientPolicyInvalidValue("deadline_merge", int(p.DeadlineMerge))
	}

	r := &resolvedPipelinePolicy{}
	switch p.ConnWait {
	case ClientPolicyConnWaitFailFast:
		r.connWaitFailFast = true
	case ClientPolicyConnWaitBlockUntilFree:
		r.connWaitBlock = true
	}
	if p.DeadlineMerge != ClientPolicyDeadlineMergeBaselineOnly && callTimeout > 0 {
		r.callTimeout = callTimeout
	}
	if p.DeadlineMerge == ClientPolicyDeadlineMergeCallCapsBaseline {
		r.capConnDeadline = true
	}
	return r, nil
}
