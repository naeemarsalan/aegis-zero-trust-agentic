package jwks

import "encoding/json"

// jsonUnmarshal is a thin alias so the fetch path reads clearly and the
// encoding/json import is isolated.
func jsonUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
