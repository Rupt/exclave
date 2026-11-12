// The EXCLAVE_LOG file as the command reads it (DESIGN.md 6.2): one line per trapped call, CALL
// RESULT PATH, the path's escapes undone, and the launcher's own lines, which carry the format's
// version. The dynamic check and prune read logs through it.

package main

import (
	"errors"
	"strconv"
	"strings"
)

// A logLine is one of an EXCLAVE_LOG file's lines (6.2): CALL RESULT PATH, the path's escapes
// undone.
type logLine struct {
	what, path string
	result     int64
}

// logVersion is the log format's version, which every launcher line carries where other lines carry
// a result (6.2): a log another format wrote is refused by name rather than misread. Format 1, whose
// escapes are format 2's but for \x, is read as well, since an older exclave's launcher may share a
// run's log with a newer one.
const logVersion = 2

// readLogs reads the log at p, refusing it when a launcher line names a format this command does
// not read.
func readLogs(p string) []logLine {
	lines := parseLog(readFile(p))
	for _, x := range lines {
		if x.what == "launcher" && (x.result < 1 || x.result > logVersion) {
			fail("%s: a launcher of log format %d wrote it; this command reads formats 1 to %d (docs/DESIGN.md 6.2)",
				p, x.result, logVersion)
		}
	}
	return lines
}

// parseLog parses an EXCLAVE_LOG file's lines, passing over any it cannot read.
func parseLog(data []byte) []logLine {
	var out []logLine
	for line := range strings.SplitSeq(string(data), "\n") {
		line = cString([]byte(line))
		sp1 := strings.IndexByte(line, ' ')
		if sp1 < 0 {
			continue
		}
		sp2 := strings.IndexByte(line[sp1+1:], ' ')
		if sp2 < 0 {
			continue
		}
		sp2 += sp1 + 1
		// CALL RESULT PATH, the result an integer (6.2)
		num := strings.TrimPrefix(line[sp1+1:sp2], "-")
		if num == "" || strings.Trim(num, "0123456789") != "" {
			continue
		}
		result, err := strconv.ParseInt(line[sp1+1:sp2], 10, 64) // a number past the range saturates, as strtol does
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			continue
		}
		out = append(out, logLine{line[:sp1], unescape(line[sp2+1:]), result})
	}
	return out
}

// unescape undoes the path's escapes in one pass from left to right (6.2): \n, \\ and, from log
// format 2, \x and two lowercase hex digits for any other control byte. A format 1 log escapes every
// backslash, so \x never begins an escape there and both formats read alike.
func unescape(p string) string {
	var o strings.Builder
	for i := 0; i < len(p); i++ {
		switch {
		case p[i] != '\\' || i+1 == len(p):
			o.WriteByte(p[i])
		case p[i+1] == 'n':
			o.WriteByte('\n')
			i++
		case p[i+1] == '\\':
			o.WriteByte('\\')
			i++
		case p[i+1] == 'x' && i+3 < len(p) && lowerHex(p[i+2]) >= 0 && lowerHex(p[i+3]) >= 0:
			o.WriteByte(byte(lowerHex(p[i+2])<<4 | lowerHex(p[i+3])))
			i += 3
		default:
			o.WriteByte(p[i])
		}
	}
	return o.String()
}

// lowerHex is c's value as a lowercase hex digit, -1 when it is not one.
func lowerHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}
