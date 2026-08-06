# Device Enrollment 2c — Server Enrollment-State Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /api/pgp/device/enrollment-state` to kypost-server so a device can report whether it can still open its local envelope, over a channel that does not depend on any push transport.

**Architecture:** One new device-authenticated handler beside the two that already exist in `pgp_device_enrollment.go`, writing through the store method that already exists (`SetNativeDeviceEncryptionEnrolled`). No schema change, no store change, no new middleware.

**Tech Stack:** Go, `net/http` with `mux.HandleFunc` pattern routing, `httptest` for handler tests.

> **This plan executes in `kypost-server`, not in the repo it is filed in.** It lives beside its spec in `kypost-android` so the two halves of one design stay together — the 2c handoff was previously split across both repos and the divergence cost real time. Target branch: `perf/bound-lockout-tests` (PR #80) or a branch off it.

**Spec:** `docs/superpowers/specs/2026-08-05-device-enrollment-2c-crypto-core-design.md`, section "Server addition (kypost-server)".

## Global Constraints

- Working directory for all commands: `/home/yoshi/git/kypost-server/backend`.
- Auth is device credentials only — `X-Kypost-Device-Id` / `X-Kypost-Device-Secret`. Never a session.
- The device id comes from the **verified credential**, never from the request body.
- `encryptionEnrolled` is **required** on this route. Absent is `400`, not "no opinion". This differs deliberately from the tri-state pointer on `register`, which stays unchanged.
- This route mutates on a device credential, so it must call `s.meterDeviceWrite` — no shared middleware meters device writes.
- Auth failures go through `writeDeviceAuthFailure(w, retryAfter)`, which handles both `401` and `429` + `Retry-After`.
- Existing behaviour must not change: the `encryptionEnrolled` field on `POST /api/notifications/native/register` stays exactly as built, for other platforms and older clients.
- `gofmt`, `go vet` clean before every commit.

## File Structure

| File | Responsibility |
|---|---|
| `internal/api/pgp_device_enrollment.go` | **Modify.** Add `handlePGPDeviceEnrollmentState` beside the two existing device-authed enrollment handlers. Same concern, same file. |
| `internal/api/server.go:557-558` | **Modify.** Register the route next to the other two `withDeviceAuth` enrollment routes. |
| `internal/api/pgp_device_enrollment_test.go` | **Modify.** Add tests using the file's existing fixtures. |

No new files. The handler is ~35 lines and belongs with its siblings.

---

### Task 1: The enrollment-state route

**Files:**
- Modify: `internal/api/pgp_device_enrollment.go` (append)
- Modify: `internal/api/server.go:558` (add one route line after it)
- Test: `internal/api/pgp_device_enrollment_test.go` (append)

**Interfaces:**
- Consumes: `s.deviceAuthFromRequest(r) (userID string, device state.NativeDevice, ok bool, retryAfter int)`; `writeDeviceAuthFailure(w, retryAfter)`; `s.meterDeviceWrite(w, r, userID) bool`; `s.userStore(userID) (*state.Store, error)`; `store.SetNativeDeviceEncryptionEnrolled(deviceID string, enrolled bool) error`; `writeJSON(w, status, any)`.
- Consumes (test fixtures, already in the test file): `newPairedDeviceForTest(t) (srv *Server, userID, deviceID string, authDevice func(*http.Request))` and `deviceByID(t, srv, userID, deviceID) state.NativeDevice`.
- Produces: `func (s *Server) handlePGPDeviceEnrollmentState(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/api/pgp_device_enrollment_test.go`:

```go
// The device's own answer to "can I still open my local envelope". Reported over
// its own route rather than on registration, because registration cannot run
// without a push token (a pull-mode device with FCM disabled has none) and on
// UnifiedPush it is driven by a third-party distributor's cycle.
func TestEnrollmentStateStoresTheReportedValue(t *testing.T) {
	for _, reported := range []bool{true, false} {
		srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)

		// Start from the opposite value so a handler that writes nothing fails.
		store, err := srv.userStore(userID)
		if err != nil {
			t.Fatalf("userStore: %v", err)
		}
		if err := store.SetNativeDeviceEncryptionEnrolled(deviceID, !reported); err != nil {
			t.Fatalf("seed: %v", err)
		}

		body := fmt.Sprintf(`{"encryptionEnrolled":%t}`, reported)
		req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-state",
			strings.NewReader(body))
		authDevice(req)
		rec := httptest.NewRecorder()
		srv.handlePGPDeviceEnrollmentState(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("reported=%t: status = %d; body=%s", reported, rec.Code, rec.Body.String())
		}
		if got := deviceByID(t, srv, userID, deviceID).EncryptionEnrolled; got != reported {
			t.Fatalf("reported=%t but stored %t", reported, got)
		}
	}
}

// Required, not tri-state. On register an absent field means "no opinion" so an
// older client is never silently marked un-enrolled. This route's only purpose
// is to state an opinion, so an absent field is a malformed request — accepting
// it as false would let a truncated body mark a working device unreadable.
func TestEnrollmentStateRequiresTheField(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if err := store.SetNativeDeviceEncryptionEnrolled(deviceID, true); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-state",
		strings.NewReader(`{}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnrollmentState(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("an absent field must leave the stored marker untouched")
	}
}

// The device id comes from the verified credential. A device that could name
// another device's id would be able to mark a healthy device unreadable, or —
// worse — mark a device readable that cannot read anything.
func TestEnrollmentStateIgnoresAnyDeviceIdInTheBody(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	otherID, _ := pairNativeDevice(t, srv, userID, "other-device")

	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-state",
		strings.NewReader(`{"encryptionEnrolled":true,"deviceId":"other-device"}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnrollmentState(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("the calling device's marker was not set")
	}
	if deviceByID(t, srv, userID, otherID).EncryptionEnrolled {
		t.Fatal("wrote onto the device named in the body, not the verified one")
	}
}

// Without credentials this must fail closed, through the same shared path every
// other device-authed route uses so the lockout counts these attempts too.
func TestEnrollmentStateRejectsAnUnauthenticatedCaller(t *testing.T) {
	srv, userID, deviceID, _ := newPairedDeviceForTest(t)

	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-state",
		strings.NewReader(`{"encryptionEnrolled":true}`))
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnrollmentState(rec, req)

	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 401 or 429; body=%s", rec.Code, rec.Body.String())
	}
	if deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("an unauthenticated call changed the marker")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run TestEnrollmentState -v
```

Expected: compile failure — `srv.handlePGPDeviceEnrollmentState undefined`. That is the correct first failure; the handler does not exist yet.

- [ ] **Step 3: Write the handler**

Append to `internal/api/pgp_device_enrollment.go`:

```go
// maxEnrollmentStateBytes bounds the state report. The body is one boolean; this
// is generous headroom and keeps an unbounded read off a device credential.
const maxEnrollmentStateBytes = 1 << 10

// handlePGPDeviceEnrollmentState records the calling device's own answer to
// "can I still open my local envelope".
//
// This exists as its own route rather than as a field on registration because
// the marker must not depend on any push transport. Registration cannot run
// without a push token, so a pull-mode device with FCM disabled could never
// restate it; and on UnifiedPush that call is driven by a third-party
// distributor's registration cycle, which must not decide when a
// security-relevant marker is refreshed.
//
// The field is REQUIRED here, unlike the tri-state pointer on registration. An
// absent field there means "no opinion" so an older client is never silently
// marked un-enrolled. Here, stating an opinion is the entire purpose, so an
// absent field is a malformed request rather than a false report.
func (s *Server) handlePGPDeviceEnrollmentState(w http.ResponseWriter, r *http.Request) {
	userID, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	// Mutates on a device credential, which no shared middleware meters.
	if !s.meterDeviceWrite(w, r, userID) {
		return
	}
	var req struct {
		EncryptionEnrolled *bool `json:"encryptionEnrolled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollmentStateBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.EncryptionEnrolled == nil {
		http.Error(w, "encryptionEnrolled is required", http.StatusBadRequest)
		return
	}
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	// device.DeviceID comes from the verified credential, never from the body.
	if err := store.SetNativeDeviceEncryptionEnrolled(device.DeviceID, *req.EncryptionEnrolled); err != nil {
		http.Error(w, "could not store the enrollment state", http.StatusInternalServerError)
		return
	}
	s.logger.Info("pgp enrollment state reported", "user_id", userID,
		"device_id", device.DeviceID, "enrolled", *req.EncryptionEnrolled)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

- [ ] **Step 4: Register the route**

In `internal/api/server.go`, immediately after the existing line 558:

```go
	mux.HandleFunc("GET /api/pgp/device/envelope", withDeviceAuth(s.handlePGPDeviceEnvelope))
	mux.HandleFunc("POST /api/pgp/device/enrollment-state", withDeviceAuth(s.handlePGPDeviceEnrollmentState))
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /home/yoshi/git/kypost-server/backend
go test ./internal/api/ -run TestEnrollmentState -v
```

Expected: all four PASS.

- [ ] **Step 6: Prove the tests are load-bearing**

Do not skip this. Two of 2b's security tests originally passed against implementations with the property removed — see `1c74842` and `00feae6`. For each mutation, re-run and confirm the named test goes red, then revert:

1. Replace `device.DeviceID` in the `SetNativeDeviceEncryptionEnrolled` call with a device id read from the body → `TestEnrollmentStateIgnoresAnyDeviceIdInTheBody` must fail.
2. Delete the `req.EncryptionEnrolled == nil` check and treat nil as `false` → `TestEnrollmentStateRequiresTheField` must fail.
3. Delete the `if !ok { writeDeviceAuthFailure(...) }` block → `TestEnrollmentStateRejectsAnUnauthenticatedCaller` must fail.

- [ ] **Step 7: Verify the whole package and formatting**

```bash
cd /home/yoshi/git/kypost-server/backend
gofmt -l ./internal/api/ && go vet ./internal/api/ && go test ./internal/api/
```

Expected: `gofmt -l` prints nothing, `go vet` silent, package tests exit 0.

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/api/pgp_device_enrollment.go \
        backend/internal/api/pgp_device_enrollment_test.go \
        backend/internal/api/server.go
git commit -m "pgp: report device enrollment state on its own route"
```

Commit body should state why the route exists rather than what it does: registration cannot carry this marker because it requires a push token a pull-mode device does not have, and because on UnifiedPush a third-party distributor drives the call.

---

### Task 2: Document the route

**Files:**
- Modify: `docs/superpowers/specs/2026-08-04-device-enrollment-design.md` (the normative spec)

**Interfaces:**
- Consumes: the handler from Task 1.
- Produces: nothing code-facing.

The three `NORMATIVE:` headings in that document are what the three client implementations are written against. A route that exists in code but not there will be re-litigated by whoever writes 2d.

- [ ] **Step 1: Add the route to the normative spec**

Add `POST /api/pgp/device/enrollment-state` to the device-authenticated route list with: device-header auth, required `encryptionEnrolled` boolean, `200 → {"ok":true}`, `400` when absent, `401`/`429` via the shared failure path, refused while the account owes a password change. State explicitly that it is required here and tri-state on `register`, and why.

- [ ] **Step 2: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add docs/superpowers/specs/2026-08-04-device-enrollment-design.md
git commit -m "docs: specify the device enrollment-state route"
```

---

## Verification before calling this done

```bash
cd /home/yoshi/git/kypost-server/backend
gofmt -l ./internal/... | tee /dev/stderr | wc -l    # must print 0
go vet ./...
go test ./...
```

Run the race detector on the touched package at CI's flags:

```bash
go test -race -timeout=20m ./internal/api/
```

`internal/api` takes several minutes under `-race`. Do not report success until it exits 0 — quote the output.
