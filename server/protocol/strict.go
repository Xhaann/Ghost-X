package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

const maxSafeInteger = 1<<53 - 1

var errMalformed = errors.New("protocol: malformed value")

func decodeObject(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errMalformed
	}

	fields := make(map[string]json.RawMessage, len(allowed))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errMalformed
		}
		key, ok := tok.(string)
		if !ok || !slices.Contains(allowed, key) {
			return nil, errMalformed
		}
		if _, dup := fields[key]; dup {
			return nil, errMalformed
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errMalformed
		}
		fields[key] = value
	}

	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errMalformed
	}
	return fields, nil
}

func decodeString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", errMalformed
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errMalformed
	}
	return s, nil
}

func decodeSafeInteger(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' || bytes.ContainsAny(raw, ".eE") {
		return 0, errMalformed
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, errMalformed
	}
	if n > maxSafeInteger {
		return 0, errMalformed
	}
	return n, nil
}
