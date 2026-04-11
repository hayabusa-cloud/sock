// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"bytes"
	"strings"

	"code.hybscloud.com/iox"
)

func copyString(dst iox.Writer, s string) error {
	_, err := iox.CopyNPolicy(dst, strings.NewReader(s), int64(len(s)), iox.YieldPolicy{})
	return err
}

func readStringN(src iox.Reader, n int) (string, error) {
	var b strings.Builder
	b.Grow(n)
	_, err := iox.CopyNPolicy(&b, src, int64(n), iox.YieldPolicy{})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func readString(src iox.Reader) (string, error) {
	var b strings.Builder
	_, err := iox.CopyPolicy(&b, src, iox.YieldPolicy{})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func echoFixed(conn iox.ReadWriter, n int) error {
	var staging bytes.Buffer
	if _, err := iox.CopyNPolicy(&staging, conn, int64(n), iox.YieldPolicy{}); err != nil {
		return err
	}
	_, err := iox.CopyNPolicy(conn, &staging, int64(staging.Len()), iox.YieldPolicy{})
	return err
}

func echoToEOF(conn iox.ReadWriter) (int64, error) {
	var staging bytes.Buffer
	if _, err := iox.CopyPolicy(&staging, conn, iox.YieldPolicy{}); err != nil {
		return 0, err
	}
	return iox.CopyPolicy(conn, &staging, iox.YieldPolicy{})
}
