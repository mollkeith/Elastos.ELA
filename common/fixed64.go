// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
)

// ErrFixed64Overflow indicates that a Fixed64 operation exceeded int64 bounds.
var ErrFixed64Overflow = errors.New("fixed64 overflow")

// ErrMoneyRange indicates that an amount fell outside the permitted range.
var ErrMoneyRange = errors.New("amount out of money range")

// MaxELAMoney is the inclusive upper bound for any single monetary amount and
// for any aggregate of amounts inside one transaction.
//
// Real ELA supply is ~26.29M ELA (~2.63e15 sela): 39,743,231 issued minus
// 13,455,469 burned. Issuance grows at ~4%/year. This bound of 1e17 sela
// (1e9 ELA) therefore sits ~38x above present supply, leaving decades of
// inflation runway.
//
// It is deliberately generous. The values it exists to reject are the crafted
// outputs of ~9.2e18 sela seen in block 2260451 -- roughly 3,500x total supply
// -- so tightening the bound buys no additional security while risking
// rejection of legitimate future activity.
//
// Note the bound alone is not what closes the exploit: each crafted output is
// individually rejected here, but the aggregate check matters independently,
// because the attack tuned three outputs whose sum wrapped past 2^64 to land
// exactly 500 sela below the input -- producing an ordinary minimum fee that
// no plausibility check would flag.
const MaxELAMoney Fixed64 = 100000000000000000

// MoneyRange reports whether value is a permissible monetary amount.
func MoneyRange(value Fixed64) bool {
	return value >= 0 && value <= MaxELAMoney
}

//the 64 bit fixed-point number, precise 10^-8
type Fixed64 int64

// AddFixed64 adds two Fixed64 values and rejects signed 64-bit overflow.
func AddFixed64(left, right Fixed64) (Fixed64, error) {
	if right > 0 && left > Fixed64(math.MaxInt64)-right {
		return 0, ErrFixed64Overflow
	}
	if right < 0 && left < Fixed64(math.MinInt64)-right {
		return 0, ErrFixed64Overflow
	}

	return left + right, nil
}

// SubtractFixed64 subtracts two Fixed64 values and rejects signed 64-bit overflow.
func SubtractFixed64(left, right Fixed64) (Fixed64, error) {
	if right > 0 && left < Fixed64(math.MinInt64)+right {
		return 0, ErrFixed64Overflow
	}
	if right < 0 && left > Fixed64(math.MaxInt64)+right {
		return 0, ErrFixed64Overflow
	}

	return left - right, nil
}

// MultiplyFixed64 multiplies two Fixed64 values and rejects signed 64-bit
// overflow. Note this is a raw integer multiply: it is correct for
// Fixed64 x scalar, and is NOT fixed-point multiplication of two monetary
// amounts (which would require dividing by 1e8).
func MultiplyFixed64(left, right Fixed64) (Fixed64, error) {
	if left == 0 || right == 0 {
		return 0, nil
	}
	if (left == Fixed64(math.MinInt64) && right == -1) ||
		(right == Fixed64(math.MinInt64) && left == -1) {
		return 0, ErrFixed64Overflow
	}

	product := left * right
	if product/right != left {
		return 0, ErrFixed64Overflow
	}

	return product, nil
}

func (f *Fixed64) Serialize(w io.Writer) error {
	return WriteElement(w, f)
}

func (f *Fixed64) Deserialize(r io.Reader) error {
	return ReadElement(r, f)
}

func (f Fixed64) IntValue() int64 {
	return int64(f)
}

func (f Fixed64) String() string {
	var buff bytes.Buffer
	value := uint64(f)
	if f < 0 {
		buff.WriteRune('-')
		value = uint64(-f)
	}
	buff.WriteString(strconv.FormatUint(value/100000000, 10))
	value %= 100000000
	if value > 0 {
		buff.WriteRune('.')
		s := strconv.FormatUint(value, 10)
		for i := len(s); i < 8; i++ {
			buff.WriteRune('0')
		}
		buff.WriteString(s)
	}
	return buff.String()
}

func (f *Fixed64) Bytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := f.Serialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Fixed64FromBytes(value []byte) (*Fixed64, error) {
	var fixed64 Fixed64
	err := fixed64.Deserialize(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}

	return &fixed64, nil
}

func StringToFixed64(s string) (*Fixed64, error) {
	var buffer bytes.Buffer
	//TODO: check invalid string
	di := strings.Index(s, ".")
	if len(s)-di > 9 {
		return nil, errors.New("unsupported precision")
	}
	if di == -1 {
		buffer.WriteString(s)
		for i := 0; i < 8; i++ {
			buffer.WriteByte('0')
		}
	} else {
		buffer.WriteString(s[:di])
		buffer.WriteString(s[di+1:])
		n := 8 - (len(s) - di - 1)
		for i := 0; i < n; i++ {
			buffer.WriteByte('0')
		}
	}
	r, err := strconv.ParseInt(buffer.String(), 10, 64)
	if err != nil {
		return nil, err
	}

	value := Fixed64(r)
	return &value, nil
}
