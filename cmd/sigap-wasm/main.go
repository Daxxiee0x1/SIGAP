//go:build js && wasm

// Command sigap-wasm exposes the SIGAP verifier to the browser demo on GitHub Pages.
// It is the same internal/verify code that runs on nodes, analyst laptops, and the vault,
// compiled to WebAssembly. Bundles never leave the visitor's browser.
//
//	GOOS=js GOARCH=wasm go build -o sigap.wasm ./cmd/sigap-wasm
package main

import (
	"encoding/json"
	"syscall/js"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/manifest"
	"github.com/Daxxiee0x1/SIGAP/internal/playground"
	"github.com/Daxxiee0x1/SIGAP/internal/truststore"
	"github.com/Daxxiee0x1/SIGAP/internal/verify"
)

func bytesFrom(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func bytesTo(b []byte) js.Value {
	u := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u, b)
	return u
}

func toJSON(v any) js.Value {
	data, _ := json.Marshal(v)
	return js.ValueOf(string(data))
}

type errorResult struct {
	Error string `json:"error"`
}

// verify(bundle: Uint8Array, trustStoreJSON: string) -> JSON string
func verifyFn(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return toJSON(errorResult{"pemakaian: verify(bundle, trustStoreJSON)"})
	}
	ts, err := truststore.Parse([]byte(args[1].String()))
	if err != nil {
		return toJSON(errorResult{"trust store tidak valid: " + err.Error()})
	}
	start := time.Now()
	r := verify.VerifyBytes(bytesFrom(args[0]), ts, verify.DefaultLimits, time.Now())
	return toJSON(struct {
		*verify.Result
		ExitCode   int   `json:"exit_code"`
		DurationUS int64 `json:"duration_us"`
	}{r, r.Status.ExitCode(), time.Since(start).Microseconds()})
}

// entries(bundle: Uint8Array) -> JSON string
func entriesFn(_ js.Value, args []js.Value) any {
	es, err := playground.Entries(bytesFrom(args[0]))
	if err != nil {
		return toJSON(errorResult{err.Error()})
	}
	return toJSON(es)
}

// edit(bundle: Uint8Array, op: "replace"|"remove"|"add", name: string, content: string)
// -> Uint8Array, or an Error object
func editFn(_ js.Value, args []js.Value) any {
	if len(args) != 4 {
		return js.Global().Get("Error").New("pemakaian: edit(bundle, op, name, content)")
	}
	out, err := playground.Edit(bytesFrom(args[0]), args[1].String(), args[2].String(), []byte(args[3].String()))
	if err != nil {
		return js.Global().Get("Error").New(err.Error())
	}
	return bytesTo(out)
}

func main() {
	api := js.Global().Get("Object").New()
	api.Set("version", manifest.AgentVersion)
	api.Set("verify", js.FuncOf(verifyFn))
	api.Set("entries", js.FuncOf(entriesFn))
	api.Set("edit", js.FuncOf(editFn))
	js.Global().Set("sigap", api)
	if ready := js.Global().Get("onSigapReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}
