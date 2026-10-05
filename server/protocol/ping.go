package protocol

import "time"

type pong struct {
	SentAt     int64 `json:"sentAt"`
	ReceivedAt int64 `json:"receivedAt"`
}

func Ping(now func() time.Time) Handler {
	return func(payload []byte) (Reply, error) {
		fields, err := decodeObject(payload, "sentAt")
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		sentAt, err := decodeSafeInteger(fields["sentAt"])
		if err != nil {
			return Reply{}, &Error{Code: CodeInvalidPayload}
		}
		return Reply{
			Type:    "pong",
			Payload: pong{SentAt: sentAt, ReceivedAt: now().UnixMilli()},
		}, nil
	}
}
