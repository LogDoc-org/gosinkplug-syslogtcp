package main

import (
	"bytes"
	"fmt"
	"github.com/LogDoc-org/gopapi"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var consumer func(entry gopapi.LogEntry) = func(entry gopapi.LogEntry) {
	fmt.Println("Passed entry: ", entry)
}

var tmpMap = make(map[string]sysMsg, 0)

func ConfigSectionName() string {
	return "syslogtcp"
}

func Configure(interface{}) {

}

func SetEntryConsumer(f func(entry gopapi.LogEntry)) {
	consumer = f
}

func SupportedTypes() []gopapi.ConnectionType {
	return []gopapi.ConnectionType{{Tcp: true, Name: "Syslog-tcp"}}
}

func Chunk(data0 []byte, source string) []byte {
	var sd, has = tmpMap[source]

	if !has {
		sd = newMsg()
		sd.src = source
		tmpMap[source] = sd
	}

	var data []byte
	if sd.data == nil {
		data = data0
	} else {
		data = append(data, sd.data[:]...)
		data = append(data, data0[:]...)
	}

	if sd.priority == -1 {
		priority(data, sd)
	} else if !sd.bsdSet {
		logType(0, data, sd)
	} else if sd.bsd {
		if len(sd.entry.SrcTime) == 0 {
			bsdDate(0, data, sd)
		} else if len(sd.entry.GetField("domain")) == 0 {
			bsdDomain(0, data, sd)
		} else {
			body(0, data, sd)
		}
	} else {
		if len(sd.entry.SrcTime) == 0 {
			date(0, data, sd)
		} else if len(sd.entry.GetField("domain")) == 0 {
			domain(0, data, sd)
		} else if len(sd.entry.AppName) == 0 {
			app(0, data, sd)
		} else if len(sd.entry.Pid) == 0 {
			pid(0, data, sd)
		} else if len(sd.entry.GetField("msgId")) == 0 {
			msgId(0, data, sd)
		} else if len(sd.structs) == 0 {
			structs(0, data, sd)
		} else {
			body(0, data, sd)
		}
	}

	return nil
}

func priority(data []byte, sd sysMsg) {
	from := 0

	for i := 0; i < len(data); i++ {
		if data[i] == '<' {
			from = i + 1
		} else if data[i] == '>' {
			sd.priority, _ = strconv.Atoi(string(data[from:i]))
			logType(i+1, data, sd)
			break
		}
	}
}

func logType(idx int, data []byte, sd sysMsg) {
	sd.bsd = !unicode.IsDigit(rune(data[idx]))
	sd.bsdSet = true
	if sd.bsd {
		bsdDate(idx, data, sd)
	} else {
		sd.version = int(data[idx])
		date(idx+1, data, sd)
	}
}

var bsdFormat = "Jan 02 15:04:05" // todo configure

func bsdDate(idx int, data []byte, sd sysMsg) {
	i := idx

	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	if len(data) < i+len(bsdFormat)-1 {
		sd.data = data[i:]
		return
	}

	if t, err := time.Parse("Jan 02 15:04:05", string(data[i:i+len(bsdFormat)])); err == nil {
		sd.entry.SrcTime = t.Format("20060102150405000")
	}

	bsdDomain(i+len(bsdFormat), data, sd)
}

func bsdDomain(idx int, data []byte, sd sysMsg) {
	i := idx

	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	for i := idx; i < len(data); i++ {
		if unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField("domain", string(data[idx:i]))
			bsdApp(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func bsdApp(idx int, data []byte, sd sysMsg) {
	i := idx

	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	for i := idx; i < len(data); i++ {
		if data[i] == ':' || unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField(gopapi.SOURCE_APP_NAME, string(data[idx:i]))
			pid(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func date(idx int, data []byte, sd sysMsg) {
	i := idx

	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	for ; i < len(data); i++ {
		if unicode.IsSpace(rune(data[i])) {
			t, _ := time.Parse("2006-01-02T15:04:05-07:00", string(data[idx:i]))

			sd.entry.SrcTime = t.Format("20060102150405000")
			domain(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func domain(idx int, data []byte, sd sysMsg) {
	for i := idx; i < len(data); i++ {
		if unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField("domain", string(data[idx:i]))
			app(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func app(idx int, data []byte, sd sysMsg) {
	for i := idx; i < len(data); i++ {
		if data[i] == '-' || unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField(gopapi.SOURCE_APP_NAME, string(data[idx:i]))
			pid(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func pid(idx int, data []byte, sd sysMsg) {
	i := idx
	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	for ; i < len(data); i++ {
		if data[i] == '-' || unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField(gopapi.PROCESS_ID, string(data[idx:i]))
			msgId(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func msgId(idx int, data []byte, sd sysMsg) {
	i := idx
	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	for ; i < len(data); i++ {
		if data[i] == '-' || unicode.IsSpace(rune(data[i])) {
			sd.entry.SetField("msgId", string(data[idx:i]))
			structs(i+1, data, sd)
			return
		}
	}

	sd.data = data[idx:]
}

func structs(idx int, data []byte, sd sysMsg) {
	i := idx
	for i < len(data)-1 && unicode.IsSpace(rune(data[i])) {
		i++
	}

	sd.structs = make([]sysStruct, 0)
	if data[i] == '[' {
		makeStruct(i, data, sd)
	} else {
		if data[i] == '-' {
			idx++
		}
		body(idx, data, sd)
	}
}

func makeStruct(idx int, data []byte, sd sysMsg) {
	var s = sysStruct{}
	//final SysStruct struct = new SysStruct();
	var (
		left  = -1
		right = -1
	)

	for i := idx; i < len(data); i++ {
		if data[i] == '[' {
			left = i
		} else if data[i] == ']' {
			right = i
		}

		if left >= 0 && right >= 1 {
			break
		}
	}

	if left == -1 || right == -1 {
		body(idx, data, sd)
		return
	}

	var (
		from = left + 1
		till = right - 1
	)

	for i := from + 1; i < till; i++ {
		if unicode.IsSpace(rune(data[i])) {
			till = i
			break
		}
	}

	s.name = strings.TrimSpace(string(data[from:till]))
	if till+1 != right {
		for till += 1; right > till && unicode.IsSpace(rune(data[till])); till++ {
			from = till

			for ; unicode.IsSpace(rune(data[from])); from++ {
			}

			for till := from; till < len(data); till++ {
				if data[till] == '=' {
					break
				}
			}
			if till < len(data)-1 && data[till+1] == '"' {
				s.tmp = strings.TrimSpace(string(data[from:till]))

				from = till + 2
				for till := from; till < len(data); till++ {
					if data[till] == '"' {
						break
					}
				}

				s.put(strings.TrimSpace(string(data[from:till])))
				sd.structs = append(sd.structs, s)
			}
		}
	}

	if len(s.values) == 0 {
		for i := 0; i < len(sd.structs); i++ {
			crnt := sd.structs[i]
			if crnt.equals(s) {
				sd.structs = append(sd.structs[:i], sd.structs[i+1:]...)
				i--
				break
			}
		}

		body(idx, data, sd)
	}

	for ; right < len(data)-1 && unicode.IsSpace(rune(data[right])); right++ {
	}

	if data[right] == '[' {
		makeStruct(right, data, sd)
	} else {
		body(right, data, sd)
	}
}

var delimiters []byte

func body(idx int, data []byte, sd sysMsg) {
	i := idx
	for ; i < len(data)-1 && unicode.IsSpace(rune(data[i])); i++ {
	}

	from := i
	till := len(data)
	if len(delimiters) != 0 {
		for ; i < len(data); i++ {
			if bytes.IndexByte(delimiters, data[i]) != -1 {
				till = i
				break
			}
		}
	}

	sd.entry.Entry = strings.TrimSpace(string(data[from:till]))
	facility := sd.priority >> 3
	level := sd.priority - (facility << 3)
	sd.entry.Level = levelMap(level)
	sd.entry.SetField("priority", strconv.Itoa(sd.priority))
	sd.entry.SetField("facility", strconv.Itoa(facility))

	bi := strings.IndexRune(sd.entry.GetField(gopapi.SOURCE_APP_NAME), '[')
	if bi > 0 {
		b2 := strings.LastIndex(sd.entry.GetField(gopapi.SOURCE_APP_NAME), "]")

		sd.entry.SetField("instId", string([]byte(sd.entry.GetField(gopapi.SOURCE_APP_NAME))[bi+1:b2]))
		sd.entry.SetField(gopapi.SOURCE_APP_NAME, string([]byte(sd.entry.GetField(gopapi.SOURCE_APP_NAME))[:bi]))
	}

	tail := sd.entry.GetField(gopapi.SOURCE_APP_NAME)
	if len(tail) == 0 {
		tail = "undef-" + sd.entry.Pid
	}
	sd.entry.Source = "syslog." + facilityName(facility) + "." + tail

	if len(sd.structs) > 0 {
		for _, s := range sd.structs {
			sd.entry.SetField("struct-id-"+s.name, s.name)
			for k, v := range s.values {
				sd.entry.SetField(k, v)
			}
		}
	}

	if sd.version > 0 {
		sd.entry.SetField("version", strconv.Itoa(sd.version))
	}

	consumer(sd.entry)
	delete(tmpMap, sd.src)

	if len(data) > till {
		Chunk(data[i:], sd.src)
	}
}

const ( // syslog levels
	LevelEmergency int = iota
	LevelAlert
	LevelCritical
	LevelError
	LevelWarn
	LevelNotice
	LevelInfo
)

func levelMap(l int) int {
	switch l {
	case LevelEmergency:
	case LevelAlert:
		return gopapi.PANIC
	case LevelCritical:
		return gopapi.SEVERE
	case LevelError:
		return gopapi.ERROR
	case LevelWarn:
		return gopapi.WARN
	case LevelNotice:
		return gopapi.LOG
	case LevelInfo:
		return gopapi.INFO
	default:
		return gopapi.DEBUG
	}

	return -1
}

func facilityName(f int) string {
	switch f {
	case 0:
		return "KERNEL"
	case 1:
		return "USER"
	case 2:
		return "MAIL"
	case 3:
		return "DAEMON"
	case 4:
		return "AUTH"
	case 5:
		return "SYSLOG"
	case 6:
		return "PRINT"
	case 7:
		return "NEWS"
	case 8:
		return "UUCP"
	case 9:
		return "CRON"
	case 10:
		return "AUTHPRIV"
	case 11:
		return "FTP"
	case 12:
		return "NTP"
	case 13:
		return "JOURNAL_AUDIT"
	case 14:
		return "JOURNAL_WARN"
	case 15:
		return "CRON_DAEMON"
	case 16:
		return "LOCAL0"
	case 17:
		return "LOCAL1"
	case 18:
		return "LOCAL2"
	case 19:
		return "LOCAL3"
	case 20:
		return "LOCAL4"
	case 21:
		return "LOCAL5"
	case 22:
		return "LOCAL6"
	default:
		return "LOCAL7"
	}
}

type sysStruct struct {
	name   string
	tmp    string
	values map[string]string
}

func (ss *sysStruct) equals(s0 sysStruct) bool {
	if !strings.EqualFold(ss.name, s0.name) || !strings.EqualFold(ss.tmp, s0.tmp) || len(ss.values) == len(s0.values) {
		return false
	}

	for k, _ := range ss.values {
		if !strings.EqualFold(ss.values[k], s0.values[k]) {
			return false
		}
	}

	return true
}

func (ss *sysStruct) put(value string) {
	ss.values[ss.name+"@@"+ss.tmp] = value
}

type sysMsg struct {
	data     []byte
	priority int
	bsd      bool
	bsdSet   bool
	version  int
	structs  []sysStruct
	src      string
	entry    gopapi.LogEntry
}

func newMsg() sysMsg {
	return sysMsg{priority: -1, structs: make([]sysStruct, 0)}
}
