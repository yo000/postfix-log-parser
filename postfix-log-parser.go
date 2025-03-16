package postfixlog

import (
	"errors"
	"regexp"
	"time"
)

const (
	SyslogPri                  = `(?:<\d{1,3}>)?`
	TimeFormat                 = "Jan  2 15:04:05"
	TimeFormatISO8601          = "2006-01-02T15:04:05.999999-07:00"
	// Capture group 1
	TimeRegexpFormat           = `([A-Za-z]{3}\s*[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}|^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:[+-][0-2]\d:[0-5]\d|Z))`
	// Capture group 2
	HostRegexpFormat           = `([0-9A-Za-z\-\.]*)`
	// Capture group 3
	ProcessRegexpFormat        = `(postfix.*(?:\/[a-z]*)+\[[0-9]{1,7}\])?`
	// Capture group 4
	QueueIdRegexpFormat        = `([0-9A-Z]*)`
	// These are the main messages : Capture group 5 get all the following
	// Capture groups 6, 7, 8, 9
	ClientRegexpFormat         = `(?:client=(.+)\[(.+)\](?:, sasl_method=(.+), sasl_username=(.+))?)?`
	// CG 10
	MessageIdRegexpFormat      = `(?:message-id=<(.+)>)?`
	// CG 11, 12, 13
	FromRegexpFormat           = `(?:from=<(.+@.+)>(?:, size=(\d+), nrcpt=(\d+))?)?`
	// CG 14, 15
	ToRegexpFormat             = `(?:to=<(.+@.+)>.*status=([a-z]+))?`
	// CG 16
	SenderNDNRegexpFormat      = `(?:sender non-delivery notification: ([0-9A-Z]*))?`
	// CG 17, 18, 19, 20, 21
	MilterRegexpFormat         = `(?:(milter-.*): .* from (.+)\[(.+)\]: .*from=<(.+@.+)?> to=<(.+@.+)> .*)?`
	// CG 22, 23, 24, 25
	AuthentFailedRegexpFormat  = `(?:warning: (.+)\[(.+)\]: SASL (.*) authentication failed: (.*))?`
	// CG 26, 27, 28, 29. from regex is voluntarily lazy, b/c some senders really do not put '@' in from
	PostfixRejectRegexpFormat  = `(?:reject: RCPT from (.+)\[(.+)\]: [0-9]{3} [0-9\.]{5} [^;]*; from=<(.+)?> to=<(.+@[^>]+)>.*$)?`
	// CG 30, 31, 32
	PostfixRLimitExceedFormat  = `(?:warning: Message delivery request rate limit exceeded: ([0-9]+) from (.+)\[(.+)\] for service [a-zA-Z]+)?`
	// CG 33, 34, 35, 36, 37, 38
	FilterRcptRegexpFormat     = `(?:filter: RCPT from (.+)\[(.+)\]: <(.+@.+)?>: ([^;]+); from=<(.+@.+)?> to=<(.+@[^>]+)> proto=[^ ]+ helo=<.+>)?`
	MessageDetailsRegexpFormat = `(` + ClientRegexpFormat + MessageIdRegexpFormat + FromRegexpFormat + ToRegexpFormat + SenderNDNRegexpFormat + MilterRegexpFormat + AuthentFailedRegexpFormat + PostfixRejectRegexpFormat + PostfixRLimitExceedFormat + FilterRcptRegexpFormat + `.*)`
	RegexpFormat               = SyslogPri + TimeRegexpFormat + ` ` + HostRegexpFormat + ` ` + ProcessRegexpFormat + `:? ` + QueueIdRegexpFormat + `(?:\: )?` + MessageDetailsRegexpFormat
)

type (
	PostfixLog struct {
		LogFormat LogFormat
		Regexp    *regexp.Regexp
	}

	LogFormat struct {
		Time           *time.Time `json:"time"`
		Hostname       string     `json:"hostname"`
		Process        string     `json:"process"`
		QueueId        string     `json:"queue_id"`
		Message       string      `json:"message"`
		ClientHostname string     `json:"client_hostname"`
		ClinetIp       string     `json:"client_ip"`
		SaslMethod     string     `json:"sasl_method"`
		SaslUsername   string     `json:"sasl_username"`
		MessageId      string     `json:"message_id"`
		From           string     `json:"from"`
		Size           string     `json:"size"`
		NRcpt          string     `json:"nrcpt"`
		To             string     `json:"to"`
		Status         string     `json:"status"`
		BounceId       string     `json:"bounce_id"`
	}
)

func NewPostfixLog() *PostfixLog {
	return &PostfixLog{
		Regexp: regexp.MustCompile(RegexpFormat),
	}
}

func (p *PostfixLog) Parse(text []byte) (LogFormat, error) {
	re := p.Regexp.Copy()
	group := re.FindSubmatch(text)
	if len(group) == 0 {
		err := errors.New("Error: Line do not match regex")
		return LogFormat{}, err
	}
	var t time.Time
	t, err := time.ParseInLocation(TimeFormat, string(group[1]), time.Local)
	if err != nil {
		t, err = time.ParseInLocation(TimeFormatISO8601, string(group[1]), time.Local)
		if err != nil {
			return LogFormat{}, err
		}
	}

	logFormat := LogFormat{
		Time:         &t,
		Hostname:     string(group[2]),
		Process:      string(group[3]),
		QueueId:      string(group[4]),
		Message:      string(group[5]),
		SaslMethod:   string(group[8]),
		SaslUsername: string(group[9]),
		MessageId:    string(group[10]),
		Size:         string(group[12]),
		NRcpt:        string(group[13]),
		BounceId:     string(group[16]),
	}

	// Milter reject|hold put values far in the group
	if len(group[17]) > 0 {
		logFormat.Status = string(group[17])
		logFormat.ClientHostname = string(group[18])
		logFormat.ClinetIp = string(group[19])
		logFormat.From = string(group[20])
		logFormat.To = string(group[21])
	// Authentication failure
	} else if len(group[22]) > 0 {
		logFormat.ClientHostname = string(group[22])
		logFormat.ClinetIp = string(group[23])
		logFormat.SaslMethod = string(group[24])
		logFormat.Status = "auth-failed"
	// postfix-reject
	} else if len(group[26]) > 0 {
		logFormat.ClientHostname = string(group[26])
		logFormat.ClinetIp = string(group[27])
		logFormat.From = string(group[28])
		logFormat.To = string(group[29])
		logFormat.Status = "postfix-reject"
	// postfix rate-limit
	} else if len(group[30]) > 0 {
		logFormat.ClientHostname = string(group[31])
		logFormat.ClinetIp = string(group[32])
		logFormat.Status = "postfix-ratelimit"
	// postfix filter RCPT
	} else if len(group[33]) > 0 {
		logFormat.ClientHostname = string(group[33])
		logFormat.ClinetIp = string(group[34])
		logFormat.From = string(group[37])
		logFormat.To = string(group[38])
		logFormat.Status = "postfix-filter"
	// bounced by remote
	} else {
		logFormat.Status = string(group[15])
		logFormat.ClientHostname = string(group[6])
		logFormat.ClinetIp = string(group[7])
		logFormat.From = string(group[11])
		logFormat.To = string(group[14])
	}

	return logFormat, nil
}
