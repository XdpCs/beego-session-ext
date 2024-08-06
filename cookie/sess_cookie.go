// Copyright 2014 beego Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cookie

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/utils"
	"github.com/beego/beego/v2/server/web/session"
)

var cookiepder = &CookieProvider{}

// CookieSessionStore Cookie SessionStore
type CookieSessionStore struct {
	sid    string
	values map[interface{}]interface{} // session data
	lock   sync.RWMutex
}

// Set value to cookie session.
// the value are encoded as gob with hash block string.
func (st *CookieSessionStore) Set(ctx context.Context, key, value interface{}) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.values[key] = value
	return nil
}

// Get value from cookie session
func (st *CookieSessionStore) Get(ctx context.Context, key interface{}) interface{} {
	st.lock.RLock()
	defer st.lock.RUnlock()
	if v, ok := st.values[key]; ok {
		return v
	}
	return nil
}

// Delete value in cookie session
func (st *CookieSessionStore) Delete(ctx context.Context, key interface{}) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	delete(st.values, key)
	return nil
}

// Flush Clean all values in cookie session
func (st *CookieSessionStore) Flush(context.Context) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.values = make(map[interface{}]interface{})
	return nil
}

// SessionID Return id of this cookie session
func (st *CookieSessionStore) SessionID(context.Context) string {
	return st.sid
}

// SessionRelease Write cookie session to http response cookie
func (st *CookieSessionStore) SessionRelease(_ context.Context, w http.ResponseWriter) {
	st.lock.RLock()
	values := st.values
	st.lock.RUnlock()
	encodedCookie, err := encodeCookie(
		cookiepder.block, cookiepder.config.SecurityKey, cookiepder.config.SecurityName, values)
	if err == nil {
		cookie := &http.Cookie{
			Name:     cookiepder.config.CookieName,
			Value:    url.QueryEscape(encodedCookie),
			Path:     "/",
			HttpOnly: true,
			Secure:   cookiepder.config.Secure,
			MaxAge:   cookiepder.config.Maxage,
		}
		http.SetCookie(w, cookie)
	}
}

// SessionReleaseIfPresent Write cookie session to http response cookie when it is present
// This is a no-op for cookie sessions, because they are always present.
func (st *CookieSessionStore) SessionReleaseIfPresent(ctx context.Context, w http.ResponseWriter) {
	st.SessionRelease(ctx, w)
}

type cookieConfig struct {
	SecurityKey  string `json:"securityKey"`
	BlockKey     string `json:"blockKey"`
	SecurityName string `json:"securityName"`
	CookieName   string `json:"cookieName"`
	Secure       bool   `json:"secure"`
	Maxage       int    `json:"maxage"`
}

// CookieProvider Cookie session provider
type CookieProvider struct {
	maxlifetime int64
	config      *cookieConfig
	block       cipher.Block
}

// SessionInit Init cookie session provider with max lifetime and config json.
// maxlifetime is ignored.
// json config:
//
//	securityKey - hash string
//	blockKey - gob encode hash string. it's saved as aes crypto.
//	securityName - recognized name in encoded cookie string
//	cookieName - cookie name
//	maxage - cookie max life time.
func (pder *CookieProvider) SessionInit(ctx context.Context, maxlifetime int64, config string) error {
	pder.config = &cookieConfig{}
	err := json.Unmarshal([]byte(config), pder.config)
	if err != nil {
		return err
	}
	if pder.config.BlockKey == "" {
		pder.config.BlockKey = string(generateRandomKey(16))
	}
	if pder.config.SecurityName == "" {
		pder.config.SecurityName = string(generateRandomKey(20))
	}
	pder.block, err = aes.NewCipher([]byte(pder.config.BlockKey))
	if err != nil {
		return err
	}
	pder.maxlifetime = maxlifetime
	return nil
}

// SessionRead Get SessionStore in cooke.
// decode cooke string to map and put into SessionStore with sid.
func (pder *CookieProvider) SessionRead(ctx context.Context, sid string) (session.Store, error) {
	maps, _ := decodeCookie(pder.block,
		pder.config.SecurityKey,
		pder.config.SecurityName,
		sid, pder.maxlifetime)
	if maps == nil {
		maps = make(map[interface{}]interface{})
	}
	rs := &CookieSessionStore{sid: sid, values: maps}
	return rs, nil
}

// SessionExist Cookie session is always existed
func (pder *CookieProvider) SessionExist(ctx context.Context, sid string) (bool, error) {
	return true, nil
}

// SessionRegenerate Implement method, no used.
func (pder *CookieProvider) SessionRegenerate(ctx context.Context, oldsid, sid string) (session.Store, error) {
	return nil, nil
}

// SessionDestroy Implement method, no used.
func (pder *CookieProvider) SessionDestroy(ctx context.Context, sid string) error {
	return nil
}

// SessionGC Implement method, no used.
func (pder *CookieProvider) SessionGC(context.Context) {
}

// SessionAll Implement method, return 0.
func (pder *CookieProvider) SessionAll(context.Context) int {
	return 0
}

// SessionUpdate Implement method, no used.
func (pder *CookieProvider) SessionUpdate(ctx context.Context, sid string) error {
	return nil
}

func init() {
	session.Register("cookie", cookiepder)
}

func encodeCookie(block cipher.Block, hashKey, name string, value map[interface{}]interface{}) (string, error) {
	var err error
	var b []byte
	// 1. EncodeGob.
	if b, err = session.EncodeGob(value); err != nil {
		return "", err
	}
	// 2. Encrypt (optional).
	if b, err = encrypt(block, b); err != nil {
		return "", err
	}
	b = encode(b)
	// 3. Create MAC for "name|date|value". Extra pipe to be used later.
	b = []byte(fmt.Sprintf("%s|%d|%s|", name, time.Now().UTC().Unix(), b))
	h := hmac.New(sha256.New, []byte(hashKey))
	h.Write(b)
	sig := h.Sum(nil)
	// Append mac, remove name.
	b = append(b, sig...)[len(name)+1:]
	// 4. Encode to base64.
	b = encode(b)
	// Done.
	return string(b), nil
}

func decodeCookie(block cipher.Block, hashKey, name, value string, gcmaxlifetime int64) (map[interface{}]interface{}, error) {
	// 1. Decode from base64.
	b, err := decode([]byte(value))
	if err != nil {
		return nil, err
	}
	// 2. Verify MAC. Value is "date|value|mac".
	parts := bytes.SplitN(b, []byte("|"), 3)
	if len(parts) != 3 {
		return nil, errors.New("Decode: invalid value format")
	}

	b = append([]byte(name+"|"), b[:len(b)-len(parts[2])]...)
	h := hmac.New(sha256.New, []byte(hashKey))
	h.Write(b)
	sig := h.Sum(nil)
	if len(sig) != len(parts[2]) || subtle.ConstantTimeCompare(sig, parts[2]) != 1 {
		return nil, errors.New("Decode: the value is not valid")
	}
	// 3. Verify date ranges.
	var t1 int64
	if t1, err = strconv.ParseInt(string(parts[0]), 10, 64); err != nil {
		return nil, errors.New("Decode: invalid timestamp")
	}
	t2 := time.Now().UTC().Unix()
	if t1 > t2 {
		return nil, errors.New("Decode: timestamp is too new")
	}
	if t1 < t2-gcmaxlifetime {
		return nil, errors.New("Decode: expired timestamp")
	}
	// 4. Decrypt (optional).
	b, err = decode(parts[1])
	if err != nil {
		return nil, err
	}
	if b, err = decrypt(block, b); err != nil {
		return nil, err
	}
	// 5. DecodeGob.
	dst, err := session.DecodeGob(b)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}

// encrypt encrypts a value using the given block in counter mode.
//
// A random initialization vector (http://goo.gl/zF67k) with the length of the
// block size is prepended to the resulting ciphertext.
func encrypt(block cipher.Block, value []byte) ([]byte, error) {
	iv := generateRandomKey(block.BlockSize())
	if iv == nil {
		return nil, errors.New("encrypt: failed to generate random iv")
	}
	// Encrypt it.
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(value, value)
	// Return iv + ciphertext.
	return append(iv, value...), nil
}

// decrypt decrypts a value using the given block in counter mode.
//
// The value to be decrypted must be prepended by an initialization vector
// (http://goo.gl/zF67k) with the length of the block size.
func decrypt(block cipher.Block, value []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(value) > size {
		// Extract iv.
		iv := value[:size]
		// Extract ciphertext.
		value = value[size:]
		// Decrypt it.
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(value, value)
		return value, nil
	}
	return nil, errors.New("decrypt: the value could not be decrypted")
}

// generateRandomKey creates a random key with the given strength.
func generateRandomKey(strength int) []byte {
	k := make([]byte, strength)
	if n, err := io.ReadFull(rand.Reader, k); n != strength || err != nil {
		return utils.RandomCreateBytes(strength)
	}
	return k
}
