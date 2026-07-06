package vfs

import "io"

// Serve runs the provider request/response loop over one connection (a socket
// to the `msb` runtime). It performs the responder half of the hello handshake,
// then reads framed CBOR requests, dispatches each to `provider`, and writes the
// reply. Requests are handled one at a time, like the sibling backends, so the
// provider never sees concurrent calls on a single connection.
//
// Serve returns nil on a clean EOF (the runtime closed the channel) and the
// underlying error on any I/O failure.
func Serve(conn io.ReadWriter, provider PathFs) error {
	if _, err := readHello(conn); err != nil {
		return err
	}
	if err := writeHello(conn); err != nil {
		return err
	}

	for {
		id, payload, err := readFrame(conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}

		var resp []byte
		if req, derr := decodeRequest(payload); derr != nil {
			// Mirrors the Rust server's decode_error_errno: a typed
			// limit-validation error (e.g. ENAMETOOLONG for an over-long
			// symlink target) keeps its errno; structural CBOR errors
			// report EINVAL.
			resp = respErr(errnoOr(derr, EINVAL))
		} else {
			resp = dispatch(provider, req)
		}
		if uint32(len(resp)) > maxFrameLen {
			resp = respErr(int32(EIO))
		}
		if err := writeFrame(conn, id, resp); err != nil {
			return err
		}
	}
}
