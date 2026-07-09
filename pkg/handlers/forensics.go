/*
Copyright 2026 The llm-d Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// DEBUG BUILD ONLY — chunk-level forensics for diagnosing corrupted
// FULL_DUPLEX_STREAMED body streams (duplicated / lost / reordered chunks
// delivered by Envoy). Not intended for upstream merge as-is.

package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"

	"github.com/go-logr/logr"
)

// forensicChunkRecord returns "offset:len:fnv32(first16):fnv32(last16)" for a chunk.
func forensicChunkRecord(offset int, body []byte) string {
	head, tail := body, body
	if len(body) > 16 {
		head = body[:16]
		tail = body[len(body)-16:]
	}
	h1 := fnv.New32a()
	h1.Write(head)
	h2 := fnv.New32a()
	h2.Write(tail)
	return fmt.Sprintf("%d:%d:%08x:%08x", offset, len(body), h1.Sum32(), h2.Sum32())
}

// logForensics analyzes a corrupted request buffer: where does valid JSON end,
// what do the trailing bytes look like, and do they duplicate an earlier
// region of the buffer (=> duplicated chunk) or not (=> foreign data).
func logForensics(logger logr.Logger, reqCtx *RequestContext, body []byte, chunks []string) {
	contentLength := ""
	if reqCtx != nil && reqCtx.Request != nil {
		contentLength = reqCtx.Request.Headers["content-length"]
	}

	// Find where the first complete JSON document ends.
	dec := json.NewDecoder(bytes.NewReader(body))
	var v any
	jsonEnd := int64(-1)
	if err := dec.Decode(&v); err == nil {
		jsonEnd = dec.InputOffset()
	}

	kv := []any{
		"totalBytes", len(body),
		"contentLength", contentLength,
		"numChunks", len(chunks),
		"jsonEndsAt", jsonEnd,
	}

	if jsonEnd >= 0 && int(jsonEnd) < len(body) {
		trailing := body[jsonEnd:]
		kv = append(kv, "trailingBytes", len(trailing))
		probe := trailing
		if len(probe) > 48 {
			probe = probe[:48]
		}
		kv = append(kv, "trailingHead", fmt.Sprintf("%q", string(probe)))
		// Does the trailing data duplicate an earlier region?
		if idx := bytes.Index(body[:jsonEnd], probe); idx >= 0 {
			kv = append(kv, "duplicateOfOffset", idx)
			// Which chunk starts nearest that offset?
			kv = append(kv, "verdict", "DUPLICATED-SLICE")
		} else {
			kv = append(kv, "verdict", "FOREIGN-TRAILING-DATA")
		}
	} else if jsonEnd < 0 {
		kv = append(kv, "verdict", "TRUNCATED-OR-INTERLEAVED (no complete JSON document)")
	}

	kv = append(kv, "chunkMap", chunks)
	logger.Info("REQUEST BODY FORENSICS", kv...)
}
