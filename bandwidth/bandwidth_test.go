package bandwidth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// zeroReader yields zero bytes forever. Used instead of allocating a large
// buffer so a test can offer far more data than the cap without the memory.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// flush pushes what has been written so far to the client, so a handler that
// then sleeps actually delays the CLIENT rather than just buffering.
func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// TestMeasureStopsAtByteCap: a server that would stream far more than the cap
// must not produce a larger sample. Without the cap the measurement is an
// unbounded transfer through a provider's tunnel -- real, paid contract
// traffic, and more than was reserved for it.
func TestMeasureStopsAtByteCap(t *testing.T) {
	offered := int64(50 * 1024 * 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, offered))
	}))
	defer srv.Close()

	bps, sampleBytes, err := Measure(context.Background(), srv.Client(), srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("Measure: %s", err)
	}
	// Exactly the cap, not merely at most: every stream is offered far more
	// than its allowance, so all StreamCount of them must stop dead on
	// StreamBytes. A "<=" assertion would pass while each stream overshot by
	// up to one 32 KiB buffer -- StreamCount buffers of unreserved paid
	// traffic through a provider's tunnel on every measurement, which is
	// precisely the bug the per-read remaining-allowance clamp exists to stop.
	if sampleBytes != MaxSampleBytes {
		t.Errorf("sampleByteCount = %d, want exactly the %d byte cap (%d streams x %d, server offered %d per stream)",
			sampleBytes, int64(MaxSampleBytes), StreamCount, StreamBytes, offered)
	}
	if bps <= 0 {
		t.Errorf("bytesPerSecond = %f, want > 0", bps)
	}
}

// TestMeasureStopsAtTimeCap: a deliberately slow server must not hold the
// measurement past its cap. A provider that trickles bytes would otherwise
// consume the whole pass.
func TestMeasureStopsAtTimeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 50; i++ {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			flush(w)
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer srv.Close()

	const cap = 2 * time.Second
	start := time.Now()
	_, sampleBytes, err := Measure(context.Background(), srv.Client(), srv.URL, cap)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Measure: %s", err)
	}
	if cap+time.Second < elapsed {
		t.Errorf("Measure ran for %s, want it to stop at the ~%s time cap", elapsed, cap)
	}
	if MaxSampleBytes <= sampleBytes {
		t.Errorf("sampleByteCount = %d: the byte cap, not the time cap, ended this measurement", sampleBytes)
	}
}

// TestMeasureExcludesWarmup: the first 500ms must not be counted in the rate.
//
// The server delivers one byte immediately, stalls past the warmup window, then
// delivers the bulk at full speed. A measurement that averaged over the whole
// transfer would report roughly the naive rate; one that discards the warmup
// reports the (much higher) steady-state rate. The assertion is against the
// naive rate computed from the same run, so it does not depend on how fast the
// test machine happens to be.
func TestMeasureExcludesWarmup(t *testing.T) {
	const bulk = 4 * 1024 * 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("x")); err != nil {
			return
		}
		flush(w)
		// stall past WarmupDuration, so everything after this lands in the
		// steady-state window and everything before it does not
		time.Sleep(WarmupDuration + 200*time.Millisecond)
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, bulk))
	}))
	defer srv.Close()

	start := time.Now()
	sample, err := MeasureTarget(context.Background(), srv.Client(),
		Target{Name: "test", URL: srv.URL}, 5*time.Second)
	wallClock := time.Since(start)
	if err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if !sample.WarmupExcluded {
		t.Fatalf("WarmupExcluded = false, want true: the transfer ran %s, well past the %s warmup",
			wallClock, WarmupDuration)
	}

	naive := float64(sample.SampleByteCount) / wallClock.Seconds()
	if sample.BytesPerSecond < 3*naive {
		t.Errorf("BytesPerSecond = %.0f, want at least 3x the warmup-inclusive rate %.0f -- the stalled first %s is being counted",
			sample.BytesPerSecond, naive, WarmupDuration)
	}
}

// TestMeasureFastTransferInsideWarmupReportsLowerBound: 16 MiB at anything
// above ~32 MiB/s completes inside the 500ms warmup window, which the fastest
// datacenter-hosted providers clear. Reporting no rate there would make the
// fastest providers -- the ones most worth measuring -- the only ones that
// never produce a figure, because the server rejects a non-positive rate
// outright. The warmup-inclusive rate is reported instead, flagged as the
// lower bound it is.
func TestMeasureFastTransferInsideWarmupReportsLowerBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, StreamBytes))
	}))
	defer srv.Close()

	sample, err := MeasureTarget(context.Background(), srv.Client(),
		Target{Name: "test", URL: srv.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if sample.Elapsed >= WarmupDuration {
		t.Skipf("this machine took %s to move %d bytes over loopback, which is not the fast case this test covers",
			sample.Elapsed, MaxSampleBytes)
	}
	if sample.BytesPerSecond <= 0 {
		t.Fatalf("BytesPerSecond = %f for a transfer that finished in %s: a fast provider must still produce a usable figure",
			sample.BytesPerSecond, sample.Elapsed)
	}
	if sample.WarmupExcluded {
		t.Errorf("WarmupExcluded = true for a transfer that finished inside the %s warmup window", WarmupDuration)
	}
}

// TestMeasureHonoursTheRequestedByteParameter: both targets are
// size-parameterised the same way, and each stream asks for exactly
// StreamBytes -- StreamCount of them add up to the cap. A target that received
// no `bytes` parameter would stream its own default instead.
func TestMeasureRequestsTheByteParameter(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.Query().Get("bytes"))
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, n))
	}))
	defer srv.Close()

	if _, err := MeasureTarget(context.Background(), srv.Client(),
		Target{Name: "test", URL: srv.URL}, 5*time.Second); err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if want := strconv.Itoa(StreamBytes); got.Load() != want {
		t.Errorf("bytes parameter = %v, want %s", got.Load(), want)
	}
}

// TestMeasureTargetSendsHeaders: the operator target is secret-gated, so the
// header has to reach it or every operator measurement is a 401.
func TestMeasureTargetSendsHeaders(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-UR-Operator-Secret"))
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, 64*1024))
	}))
	defer srv.Close()

	target := OperatorTarget(srv.URL, "s3cret")
	if _, err := MeasureTarget(context.Background(), srv.Client(), target, 5*time.Second); err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if got.Load() != "s3cret" {
		t.Errorf("X-UR-Operator-Secret = %v, want the configured secret", got.Load())
	}
}

// throttledHandler serves total bytes at approximately bytesPerSecond, in
// chunks, so two test targets can be given genuinely different speeds.
func throttledHandler(total int64, chunk int64, pause time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var written int64
		for written < total {
			n := chunk
			if remaining := total - written; remaining < n {
				n = remaining
			}
			if _, err := io.Copy(w, io.LimitReader(zeroReader{}, n)); err != nil {
				return
			}
			flush(w)
			written += n
			time.Sleep(pause)
		}
	}
}

type recordingReserver struct {
	mu    sync.Mutex
	calls []int64
	err   error
}

func (r *recordingReserver) ReserveBandwidth(ctx context.Context, providerClientId string, byteCount int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, byteCount)
	return r.err
}

// reserved returns every byte count that was reserved, in call order.
func (r *recordingReserver) reserved() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.calls...)
}

func (r *recordingReserver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type submission struct {
	clientId        string
	source          string
	bytesPerSecond  float64
	sampleByteCount int64
}

type recordingSubmitter struct {
	mu   sync.Mutex
	subs []submission
	err  error
}

func (s *recordingSubmitter) SubmitBandwidth(
	ctx context.Context,
	providerClientId string,
	source string,
	bytesPerSecond float64,
	sampleByteCount int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs = append(s.subs, submission{providerClientId, source, bytesPerSecond, sampleByteCount})
	return s.err
}

func (s *recordingSubmitter) all() []submission {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]submission(nil), s.subs...)
}

// TestSamplerReportsTargetsSeparately is the property the second target exists
// for: a provider that prioritises one path and not the other is invisible in
// a single combined figure and obvious in two. The two servers here run at
// deliberately different speeds, and each target's reported figure must track
// its OWN server -- never the mean of the pair, which is what a combined figure
// would be and what would erase the divergence.
func TestSamplerReportsTargetsSeparately(t *testing.T) {
	// ~4 MiB in one go: fast
	fast := httptest.NewServer(throttledHandler(4*1024*1024, 4*1024*1024, 0))
	defer fast.Close()
	// ~1 MiB in 64 KiB chunks with a pause between each: much slower
	slow := httptest.NewServer(throttledHandler(1024*1024, 64*1024, 40*time.Millisecond))
	defer slow.Close()

	reserver := &recordingReserver{}
	submitter := &recordingSubmitter{}
	sampler := &Sampler{
		Targets: []Target{
			{Name: "operator", Source: SourceOperator, URL: fast.URL},
			{Name: "cdn", Source: SourceCDN, URL: slow.URL},
		},
		Reserve: reserver,
		Submit:  submitter,
		Timeout: 5 * time.Second,
	}

	results := sampler.Sample(context.Background(), "provider-1", fast.Client())

	if len(results) != 2 {
		t.Fatalf("got %d results, want one per target", len(results))
	}
	for _, r := range results {
		if !r.Measured() {
			t.Fatalf("%s: not measured (skip=%q err=%v)", r.Target.Name, r.Skip, r.Err)
		}
	}

	operator, cdn := results[0], results[1]
	if operator.Target.Source != SourceOperator || cdn.Target.Source != SourceCDN {
		t.Fatalf("results carry the wrong sources: %q, %q", operator.Target.Source, cdn.Target.Source)
	}
	if operator.Sample.BytesPerSecond <= cdn.Sample.BytesPerSecond {
		t.Fatalf("operator=%.0f B/s cdn=%.0f B/s: the deliberately faster target did not measure faster, so the two figures are not tracking their own targets",
			operator.Sample.BytesPerSecond, cdn.Sample.BytesPerSecond)
	}

	// the mean is what a combined figure would be. Neither reported figure may
	// be it: if both collapsed onto the mean the divergence above is gone.
	mean := (operator.Sample.BytesPerSecond + cdn.Sample.BytesPerSecond) / 2
	for _, r := range results {
		if withinOnePercent(r.Sample.BytesPerSecond, mean) {
			t.Errorf("%s reported %.0f B/s, which is the mean of the two targets (%.0f B/s) -- the figures are being averaged, which destroys the divergence signal",
				r.Target.Name, r.Sample.BytesPerSecond, mean)
		}
	}

	// and they must be STORED separately: one submission per target, each under
	// its own source tag, each carrying its own figure
	subs := submitter.all()
	if len(subs) != 2 {
		t.Fatalf("got %d submissions, want one per target -- two targets must never be stored as one figure", len(subs))
	}
	bySource := map[string]submission{}
	for _, s := range subs {
		bySource[s.source] = s
	}
	if len(bySource) != 2 {
		t.Fatalf("submissions carry %d distinct sources, want 2 (%s and %s)", len(bySource), SourceOperator, SourceCDN)
	}
	for _, r := range results {
		s, ok := bySource[r.Target.Source]
		if !ok {
			t.Fatalf("no submission for source %q", r.Target.Source)
		}
		if s.bytesPerSecond != r.Sample.BytesPerSecond {
			t.Errorf("source %q submitted %.0f B/s but measured %.0f B/s",
				r.Target.Source, s.bytesPerSecond, r.Sample.BytesPerSecond)
		}
		if s.sampleByteCount != r.Sample.SampleByteCount {
			t.Errorf("source %q submitted a %d byte sample but measured %d bytes",
				r.Target.Source, s.sampleByteCount, r.Sample.SampleByteCount)
		}
	}

	if reserver.count() != 2 {
		t.Errorf("%d reservations, want one per target: each target pulls its own sample through the provider's tunnel", reserver.count())
	}
	// A reservation has to be for what the measurement actually moves. The
	// server clamps a reservation to model.MaxProviderBandwidthBytesPerProbe,
	// so if this figure ever drifts above that constant the deployment-wide
	// budget silently under-counts every probe -- worse than having no budget.
	for _, reserved := range reserver.reserved() {
		if reserved != MaxSampleBytes {
			t.Errorf("reserved %d bytes for a measurement that transfers up to %d: the byte budget must reserve what is actually pulled",
				reserved, int64(MaxSampleBytes))
		}
	}
}

func withinOnePercent(a float64, b float64) bool {
	if b == 0 {
		return a == 0
	}
	d := (a - b) / b
	return -0.01 < d && d < 0.01
}

// TestSamplerSkipsCleanlyWhenBudgetExhausted: a 429 from the reserve endpoint
// is a clean skip. It must not be a failure, and -- the part that actually
// costs money if it is wrong -- it must not measure anyway. An unreserved
// measurement pulls 5 MiB of paid contract traffic through a provider's tunnel
// that the deployment's hourly budget never admitted.
func TestSamplerSkipsCleanlyWhenBudgetExhausted(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, MaxSampleBytes))
	}))
	defer srv.Close()

	cases := []struct {
		name       string
		reserveErr error
		wantSkip   string
		wantErr    bool
	}{
		{
			name:       "budget exhausted",
			reserveErr: fmt.Errorf("reserve provider-1: %w", ErrNoBudget),
			wantSkip:   SkipNoBudget,
		},
		{
			name:       "reservation failed for another reason",
			reserveErr: errors.New("server unreachable"),
			wantErr:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requests.Store(0)
			submitter := &recordingSubmitter{}
			sampler := &Sampler{
				Targets: []Target{
					{Name: "operator", Source: SourceOperator, URL: srv.URL},
					{Name: "cdn", Source: SourceCDN, URL: srv.URL},
				},
				Reserve: &recordingReserver{err: c.reserveErr},
				Submit:  submitter,
			}

			results := sampler.Sample(context.Background(), "provider-1", srv.Client())

			if len(results) != len(sampler.Targets) {
				t.Fatalf("got %d results, want one per target", len(results))
			}
			for _, r := range results {
				if r.Skip != c.wantSkip {
					t.Errorf("%s: skip = %q, want %q", r.Target.Name, r.Skip, c.wantSkip)
				}
				if (r.Err != nil) != c.wantErr {
					t.Errorf("%s: err = %v, wantErr = %t", r.Target.Name, r.Err, c.wantErr)
				}
				if r.Measured() {
					t.Errorf("%s: reported a measurement despite no reservation", r.Target.Name)
				}
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("%d request(s) reached the target without a reservation, want 0 -- an unreserved measurement spends byte budget the deployment did not admit", n)
			}
			if subs := submitter.all(); len(subs) != 0 {
				t.Errorf("%d submission(s) for an unmeasured provider, want 0", len(subs))
			}
		})
	}
}

// TestSamplerSkipsWhenTheProbeHasNoTimeLeft: the bandwidth sample rides along
// on a probe whose budget geolocation and egress-health have already spent. A
// measurement started on an exhausted deadline describes the prober's clock,
// not the provider -- and reserving budget for it would charge the fleet for
// nothing.
func TestSamplerSkipsWhenTheProbeHasNoTimeLeft(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	reserver := &recordingReserver{}
	sampler := &Sampler{
		Targets: []Target{{Name: "operator", Source: SourceOperator, URL: srv.URL}},
		Reserve: reserver,
		Submit:  &recordingSubmitter{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), MinTimeBudget/10)
	defer cancel()

	results := sampler.Sample(ctx, "provider-1", srv.Client())
	if len(results) != 1 || results[0].Skip != SkipNoTime {
		t.Fatalf("got %+v, want a single %q skip", results, SkipNoTime)
	}
	if reserver.count() != 0 {
		t.Errorf("%d reservation(s) taken for a measurement that could not run", reserver.count())
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d request(s) made with no time budget left, want 0", n)
	}
}

// TestSummaryShowsBothFiguresSideBySide: the log line is the operator's only
// view of divergence between the two targets, so both figures are always
// present, always labelled, and a skip says so explicitly rather than going
// missing (a missing figure reads as "nothing measured" when the truth is "the
// budget was reached").
func TestSummary(t *testing.T) {
	operator := Target{Name: "operator", Source: SourceOperator}
	cdn := Target{Name: "cdn", Source: SourceCDN}

	cases := []struct {
		name    string
		results []Result
		want    string
	}{
		{
			name: "both measured",
			results: []Result{
				{Target: operator, Sample: Sample{BytesPerSecond: 12.4 * 1024 * 1024, WarmupExcluded: true}},
				{Target: cdn, Sample: Sample{BytesPerSecond: 11.8 * 1024 * 1024, WarmupExcluded: true}},
			},
			want: "operator=12.4MB/s cdn=11.8MB/s",
		},
		{
			name: "warmup-inclusive figures are flagged as lower bounds",
			results: []Result{
				{Target: operator, Sample: Sample{BytesPerSecond: 46.9 * 1024 * 1024}},
				{Target: cdn, Sample: Sample{BytesPerSecond: 11.8 * 1024 * 1024, WarmupExcluded: true}},
			},
			want: "operator=46.9MB/s(lower-bound) cdn=11.8MB/s",
		},
		{
			name: "a budget skip says so",
			results: []Result{
				{Target: operator, Sample: Sample{BytesPerSecond: 12.4 * 1024 * 1024, WarmupExcluded: true}},
				{Target: cdn, Skip: SkipNoBudget},
			},
			want: "operator=12.4MB/s cdn=skipped(no byte budget this hour)",
		},
		{
			name: "a failure is not a skip",
			results: []Result{
				{Target: operator, Err: errors.New("boom")},
				{Target: cdn, Skip: SkipNoTime},
			},
			want: "operator=failed(boom) cdn=skipped(no time left in this probe)",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Summary(c.results); got != c.want {
				t.Errorf("Summary() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTargetHostsCoversBothTargets: a host that is neither pinned nor in the
// tunnel's allowlist is refused by the tunnel dialer, so every measurement
// would fail before it started if a target host were missing here.
func TestTargetHosts(t *testing.T) {
	hosts := TargetHosts(DefaultTargets("https://api.example.net", "secret"))
	joined := strings.Join(hosts, ",")
	for _, want := range []string{"api.example.net", "speed.cloudflare.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("TargetHosts() = %v, missing %q", hosts, want)
		}
	}
}

// barrierServer is an httptest server that counts the connections it accepts
// and holds every request open until `want` of them are in flight at once.
//
// Connections, not requests: N requests multiplexed over one HTTP/2 connection
// share one congestion window, which is exactly the failure this whole change
// exists to fix. A request counter cannot see the difference; a connection
// counter can.
type barrierServer struct {
	srv     *httptest.Server
	conns   atomic.Int64
	arrived atomic.Int64
	all     chan struct{}
	once    sync.Once
}

func newBarrierServer(t *testing.T, want int, body func(w http.ResponseWriter)) *barrierServer {
	t.Helper()
	b := &barrierServer{all: make(chan struct{})}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(b.arrived.Add(1)) == want {
			b.once.Do(func() { close(b.all) })
		}
		select {
		case <-b.all:
		case <-time.After(10 * time.Second):
			t.Errorf("only %d of %d requests were ever in flight at once", b.arrived.Load(), want)
			return
		}
		body(w)
	}))
	b.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			b.conns.Add(1)
		}
	}
	b.srv.Start()
	t.Cleanup(b.srv.Close)
	return b
}

// TestMeasureOpensStreamCountConnections: the measurement must actually open
// StreamCount transport connections, simultaneously.
//
// This is the fix itself, asserted directly. A single TCP flow cannot exceed
// (connect's 1 MiB MaxWindowSize / RTT) regardless of how much capacity the
// provider has -- which is why the single-stream version of this package
// reported ~1 MiB / RTT for eleven of twelve beta providers, and 4.8 MB/s for
// a provider independently measured at 79 MB/s on its own host. N flows get N
// windows; anything that quietly collapses them back to one (a serialised
// loop, a connection pool of one, HTTP/2 multiplexing) restores the original
// bug with every other test still green.
func TestMeasureOpensStreamCountConnections(t *testing.T) {
	b := newBarrierServer(t, StreamCount, func(w http.ResponseWriter) {
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, StreamBytes))
	})

	sample, err := MeasureTarget(context.Background(), b.srv.Client(),
		Target{Name: "test", URL: b.srv.URL}, 30*time.Second)
	if err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if got := b.conns.Load(); got != StreamCount {
		t.Fatalf("the server accepted %d connections, want %d: %d parallel streams are only %d congestion windows if they are %d connections",
			got, StreamCount, StreamCount, StreamCount, StreamCount)
	}
	if sample.Streams != StreamCount {
		t.Errorf("Sample.Streams = %d, want %d", sample.Streams, StreamCount)
	}
	if want := int64(MaxSampleBytes); sample.SampleByteCount != want {
		t.Errorf("SampleByteCount = %d, want %d (%d streams x %d)",
			sample.SampleByteCount, want, StreamCount, StreamBytes)
	}
}

// TestMeasureAggregatesAcrossParallelStreams is the point of the change stated
// as an assertion: against a target that rate-limits EACH CONNECTION to the
// same figure -- which is what connect's per-flow window does to a real
// provider -- the parallel measurement must report about StreamCount times
// what one connection can carry, not one connection's worth.
//
// The single-stream baseline is measured from the same handler in the same
// run, so the assertion does not depend on how fast this machine is.
func TestMeasureAggregatesAcrossParallelStreams(t *testing.T) {
	// ~1.6 MiB/s per connection: 32 KiB every 20 ms. StreamBytes then takes
	// ~1.25 s per stream, comfortably past the 500 ms warmup, so the figure
	// under test is a real steady-state one.
	const chunk = 32 * 1024
	const pause = 20 * time.Millisecond
	srv := httptest.NewServer(throttledHandler(StreamBytes, chunk, pause))
	defer srv.Close()

	// baseline: one connection, StreamBytes, same handler, timed by hand
	sizedOne, err := sizedURL(srv.URL, StreamBytes)
	if err != nil {
		t.Fatal(err)
	}
	singleStart := time.Now()
	resp, err := srv.Client().Get(sizedOne)
	if err != nil {
		t.Fatalf("baseline request: %s", err)
	}
	singleBytes, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("baseline read: %s", err)
	}
	singleRate := float64(singleBytes) / time.Since(singleStart).Seconds()

	sample, err := MeasureTarget(context.Background(), srv.Client(),
		Target{Name: "test", URL: srv.URL}, 30*time.Second)
	if err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if !sample.WarmupExcluded {
		t.Fatalf("the transfer finished inside the warmup window (%s), so this run is not measuring the steady state it claims to", sample.Elapsed)
	}

	t.Logf("per-connection %.0f B/s, aggregate %.0f B/s over %s (%d streams, %d bytes)",
		singleRate, sample.BytesPerSecond, sample.Elapsed, sample.Streams, sample.SampleByteCount)

	// measurably higher than one stream. Half the theoretical StreamCount
	// multiple is a wide margin that a serialised or multiplexed
	// implementation cannot reach and a working one clears easily.
	if floor := float64(StreamCount) / 2 * singleRate; sample.BytesPerSecond < floor {
		t.Fatalf("aggregate = %.0f B/s against a per-connection rate of %.0f B/s, want at least %.0f. "+
			"%d parallel streams are not adding up -- the measurement is still reporting one stream's throughput",
			sample.BytesPerSecond, singleRate, floor, StreamCount)
	}

	// and it must be the SUM, not something larger: summing per-stream rates
	// instead of dividing summed bytes by one common window would report
	// throughput the link never simultaneously carried.
	want := float64(StreamCount) * singleRate
	if ratio := sample.BytesPerSecond / want; ratio < 0.6 || 1.4 < ratio {
		t.Errorf("aggregate = %.0f B/s, want ~%.0f (%d x the %.0f B/s per-connection rate); ratio %.2f",
			sample.BytesPerSecond, want, StreamCount, singleRate, ratio)
	}
}

// unalignedBody yields exactly chunk bytes per Read, forever. A real
// connection does the same thing -- a Read returns whatever happens to have
// arrived, not a whole buffer -- and the sizes it returns are not multiples of
// the read buffer. Over loopback an httptest server happens to fill the 32 KiB
// buffer every time, which hides an off-by-one-buffer cap bug completely, so
// this stubs the transport instead of relying on that accident.
type unalignedBody struct{ chunk int }

func (b unalignedBody) Read(p []byte) (int, error) {
	n := b.chunk
	if len(p) < n {
		n = len(p)
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	return n, nil
}

func (unalignedBody) Close() error { return nil }

// stubTransport answers every request from an unalignedBody and counts the
// requests it saw.
type stubTransport struct {
	chunk    int
	requests atomic.Int64
}

func (t *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.requests.Add(1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       unalignedBody{chunk: t.chunk},
		Request:    r,
	}, nil
}

// TestMeasureCapsEachStreamOnItsRemainingAllowance: the byte cap is enforced
// against what is left of a stream's allowance, not per read.
//
// Reading a whole buffer and checking the total afterwards overshoots by up to
// one buffer PER STREAM -- StreamCount buffers of paid contract traffic
// through a provider's tunnel that the server's byte budget never admitted, on
// every single measurement. The stub delivers a chunk size that shares no
// factor with either the read buffer or StreamBytes, so an overshoot cannot
// hide behind an accidentally-aligned read.
func TestMeasureCapsEachStreamOnItsRemainingAllowance(t *testing.T) {
	tr := &stubTransport{chunk: 7000}
	client := &http.Client{Transport: tr}

	sample, err := MeasureTarget(context.Background(), client,
		Target{Name: "test", URL: "https://stub.example/download"}, 30*time.Second)
	if err != nil {
		t.Fatalf("MeasureTarget: %s", err)
	}
	if want := int64(MaxSampleBytes); sample.SampleByteCount != want {
		t.Errorf("SampleByteCount = %d, want exactly %d: %d bytes over the cap, across %d streams reading %d-byte chunks",
			sample.SampleByteCount, want, sample.SampleByteCount-want, StreamCount, tr.chunk)
	}
	if got := tr.requests.Load(); got != StreamCount {
		t.Errorf("%d requests, want %d", got, StreamCount)
	}
}
