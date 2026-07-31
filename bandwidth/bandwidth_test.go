package bandwidth

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	if MaxSampleBytes < sampleBytes {
		t.Errorf("sampleByteCount = %d, exceeded the %d byte cap (server offered %d)",
			sampleBytes, MaxSampleBytes, offered)
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

// TestMeasureFastTransferInsideWarmupReportsLowerBound: 5 MiB at anything
// above ~10 MB/s completes inside the 500ms warmup window, which is the normal
// case for a datacenter-hosted provider. Reporting no rate there would make the
// fastest providers -- the ones most worth measuring -- the only ones that
// never produce a figure, because the server rejects a non-positive rate
// outright. The warmup-inclusive rate is reported instead, flagged as the
// lower bound it is.
func TestMeasureFastTransferInsideWarmupReportsLowerBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, MaxSampleBytes))
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
// size-parameterised the same way, and the measurement asks for exactly the
// cap. A target that received no `bytes` parameter would stream its own
// default instead.
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
	if want := strconv.Itoa(MaxSampleBytes); got.Load() != want {
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
