// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sequence

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/zhenjl/porter2"
)

var (
	config struct {
		tagIDs   map[string]TagType
		tagNames []string
		tagTypes []TokenType
	}

	keymaps struct {
		keywords map[string]TagType
		prekeys  map[string][]TagType
	}

	TagTypesCount   int
	TokenTypesCount = int(token__END__) + 1
	allTypesCount   int
)

var configRaw = `
	version = "0.1"
timeFormats = [
	"Mon Jan _2 15:04:05 2006",
	"Mon Jan _2 15:04:05 MST 2006",
	"Mon Jan 02 15:04:05 -0700 2006",
	"02 Jan 06 15:04 MST",
	"02 Jan 06 15:04 -0700",
	"Monday, 02-Jan-06 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"Jan _2 15:04:05",
	"Jan _2 15:04:05.000",
	"Jan _2 15:04:05.000000",
	"Jan _2 15:04:05.000000000",
	"_2/Jan/2006:15:04:05 -0700",
	"Jan 2, 2006 3:04:05 PM",
	"Jan 2 2006 15:04:05",
	"Jan 2 15:04:05 2006",
	"Jan 2 15:04:05 -0700",
	"2006-01-02 15:04:05,000 -0700",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05-0700",
	"2006-01-02 15:04:05,000",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	"06-01-02 15:04:05,000 -0700",
	"06-01-02 15:04:05,000",
	"06-01-02 15:04:05",
	"06/01/02 15:04:05",
	"15:04:05,000",
	"1/2/2006 3:04:05 PM",
	"1/2/06 3:04:05.000 PM",
	"1/2/2006 15:04",
	"2016-12-14",
	"02Jan2006 03:04:05",
	"Jan _2, 2006 3:04:05 PM",
	"12/14/16 3:46:41.409 PM",
	"12/14/16 3:46:41.409 AM",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05.999-0700",
	"2006-01-02",
	"15:04:05",
	"2006-01-02T15:04:05.999999Z",
	"02/Jan/2006:15:04:05.999"
]
tags = [
	"filesAdded:integer",		# The number of files added
	"filesDeleted:integer",		# The number of lines deleted
	"filepath:string", 			# The file path
	"authorfirst:string",		# The author of the commit
	"authorlast:string",		# The author of the commit
	"commitid:string",			# The commit id
	"commitidint:integer",		# the git commit id as an integer
	"msgid:string",				# The message identifier
	"msgtime:time",				# The timestamp that’s part of the log message
	"severity:integer",			# The severity of the event, e.g., Emergency, …
	"priority:integer",			# The pirority of the event
	"apphost:string",			# The hostname of the host where the log message is generated
	"appip:ipv4",				# The IP address of the host where the application that generated the log message is running on.
	"appvendor:string",			# The type of application that generated the log message, e.g., Cisco, ISS
	"appname:string",			# The name of the application that generated the log message, e.g., asa, snort, sshd
	"srcdomain:string",			# The domain name of the initiator of the event, usually a Windows domain
	"srczone:string",			# The originating zone
	"srchost:string",			# The hostname of the originator of the event or connection.
	"srcip:ipv4",				# The IPv4 address of the originator of the event or connection.
	"srcipnat:ipv4",			# The natted (network address translation) IP of the originator of the event or connection.
	"srcport:integer",			# The port number of the originating connection.
	"srcportnat:integer",		# The natted port number of the originating connection.
	"srcmac:mac",				# The mac address of the host that originated the connection.
	"srcuser:string",			# The user that originated the session.
	"srcuid:integer",			# The user id that originated the session.
	"srcgroup:string",			# The group that originated the session.
	"srcgid:integer",			# The group id that originated the session.
	"srcemail:string",			# The originating email address
	"dstdomain:string",			# The domain name of the destination of the event, usually a Windows domain
	"dstzone:string",			# The destination zone
	"dsthost:string",			# The hostname of the destination of the event or connection.
	"dstip:ipv4",				# The IPv4 address of the destination of the event or connection.
	"dstipnat:ipv4",			# The natted (network address translation) IP of the destination of the event or connection.
	"dstport:integer",			# The destination port number of the connection.
	"dstportnat:integer",		# The natted destination port number of the connection.
	"dstmac:mac",				# The mac address of the destination host.
	"dstuser:string",			# The user at the destination.
	"dstuid:integer",			# The user id that originated the session.
	"dstgroup:string",			# The group that originated the session.
	"dstgid:integer",			# The group id that originated the session.
	"dstemail:string",			# The destination email address
	"protocol:string",			# The protocol, such as TCP, UDP, ICMP, of the connection
	"iniface:string",			# The incoming interface
	"outiface:string",			# The outgoing interface
	"policyid:integer",			# The policy ID
	"sessionid:integer",		# The session or process ID
	"object:string",			# The object affected.
	"action:string",			# The action taken
	"command:string",			# The command executed
	"method:string",			# The method in which the action was taken, for example, public key or password for ssh
	"status:string",			# The status of the action taken
	"reason:string",			# The reason for the action taken or the status returned
	"bytesrecv:integer",		# The number of bytes received
	"bytessent:integer",		# The number of bytes sent
	"pktsrecv:integer",			# The number of packets received
	"pktssent:integer",			# The number of packets sent
	"duration:integer"			# The duration of the session
]
[analyzer]
	[analyzer.prekeys]
	address		= [ "srchost", "srcipv4" ]
	by 			= [ "srchost", "srcipv4", "srcuser" ]
	command 	= [ "command" ]
	connection 	= [ "sessionid" ]
	dport		= [ "dstport" ]
	dst 		= [ "dsthost", "dstipv4" ]
	duration	= [ "duration" ]
	egid 		= [ "srcgid" ]
	euid 		= [ "srcuid" ]
	for 		= [ "srchost", "srcipv4", "srcuser" ]
	from 		= [ "srchost", "srcipv4" ]
	gid 		= [ "srcgid" ]
	group 		= [ "srcgroup" ]
	logname 	= [ "srcuser" ]
	port 		= [ "srcport", "dstport" ]
	proto		= [ "protocol" ]
	rhost 		= [ "srchost", "srcipv4" ]
	ruser 		= [ "srcuser" ]
	sport		= [ "srcport" ]
	src 		= [ "srchost", "srcipv4" ]
	time 		= [ "msgtime" ]
	to 			= [ "dsthost", "dstipv4", "dstuser" ]
	uid 		= [ "srcuid" ]
	uname 		= [ "srcuser" ]
	user 		= [ "srcuser" ]
	[analyzer.keywords]
	action = [
		"access",
		"alert",
		"allocate",
		"allow",
		"audit",
		"authenticate",
		"backup",
		"bind",
		"block",
		"build",
		"built",
		"cancel",
		"clean",
		"close",
		"compress",
		"connect",
		"copy",
		"create",
		"decode",
		"decompress",
		"decrypt",
		"depress",
		"detect",
		"disconnect",
		"download",
		"encode",
		"encrypt",
		"establish",
		"execute",
		"filter",
		"find",
		"free",
		"get",
		"initialize",
		"initiate",
		"install",
		"lock",
		"login",
		"logoff",
		"logon",
		"logout",
		"modify",
		"move",
		"open",
		"post",
		"quarantine",
		"read",
		"release",
		"remove",
		"replicate",
		"resume",
		"save",
		"scan",
		"search",
		"start",
		"stop",
		"suspend",
		"teardown",
		"uninstall",
		"unlock",
		"update",
		"upgrade",
		"upload",
		"violate",
		"write"
	]
	status = [
		"accept",
		"error",
		"fail",
		"failure",
		"success"
	]
	object = [
		"account",
		"app",
		"bios",
		"driver",
		"email",
		"event",
		"file",
		"flow",
		"connection",
		"memory",
		"packet",
		"process",
		"rule",
		"session",
		"system",
		"thread",
		"vuln"
	]
	srcuser = [
		"root",
		"admin",
		"administrator"
	]
	method = [
		"password",
		"publickey"
	]
	protocol = [
		"udp",
		"tcp",
		"icmp",
		"http/1.0",
		"http/1.1"
	]
`

func ReadConfig(file string) error {
	var configInfo struct {
		Version       string
		TimeFormats   []string
		CommitFormats []string
		Tags          []string

		Analyzer struct {
			Prekeys  map[string][]string
			Keywords map[string][]string
		}
	}

	toml.Decode(string(configRaw), &configInfo)

	timeFsmRoot = buildTimeFSM(configInfo.TimeFormats)

	config.tagIDs = make(map[string]TagType, 30)
	config.tagNames = config.tagNames[:0]
	config.tagTypes = config.tagTypes[:0]

	keymaps.keywords = make(map[string]TagType, 30)
	keymaps.prekeys = make(map[string][]TagType, 30)

	var ftype TagType = 0
	config.tagIDs["funknown"] = ftype
	config.tagNames = append(config.tagNames, "funknown")
	config.tagTypes = append(config.tagTypes, TokenUnknown)
	ftype++

	for _, f := range configInfo.Tags {
		fs := strings.Split(f, ":")
		if len(fs) != 2 || fs[1] == "" {
			return fmt.Errorf("Error parsing tag %q: missing token type", f)
		}

		// tag type name, token type
		tt := name2TokenType(fs[1])
		if tt < TokenLiteral || tt > TokenString {
			return fmt.Errorf("Error parsing tag %q: invalid token type", f)
		}

		config.tagIDs[fs[0]] = ftype
		config.tagNames = append(config.tagNames, fs[0])
		config.tagTypes = append(config.tagTypes, tt)
		ftype++
	}

	for f, t := range config.tagIDs {
		predefineAnalyzerTags(f, t)
	}

	for w, list := range configInfo.Analyzer.Keywords {
		if f, ok := config.tagIDs[w]; ok {
			for _, kw := range list {
				pw := porter2.Stem(kw)
				keymaps.keywords[pw] = f
			}
		}
	}

	for w, m := range configInfo.Analyzer.Prekeys {
		for _, fw := range m {
			if f, ok := config.tagIDs[fw]; ok {
				keymaps.prekeys[w] = append(keymaps.prekeys[w], f)
			}
		}
	}

	TagTypesCount = len(config.tagNames)
	allTypesCount = TokenTypesCount + TagTypesCount

	return nil
}

func predefineAnalyzerTags(f string, t TagType) {
	switch f {
	case "msgid":
		TagMsgId = t
	case "msgtime":
		TagMsgTime = t
	case "severity":
		TagSeverity = t
	case "priority":
		TagPriority = t
	case "apphost":
		TagAppHost = t
	case "appip":
		TagAppIP = t
	case "appvendor":
		TagAppVendor = t
	case "appname":
		TagAppName = t
	case "srcdomain":
		TagSrcDomain = t
	case "srczone":
		TagSrcZone = t
	case "srchost":
		TagSrcHost = t
	case "srcip":
		TagSrcIP = t
	case "srcipnat":
		TagSrcIPNAT = t
	case "srcport":
		TagSrcPort = t
	case "srcportnat":
		TagSrcPortNAT = t
	case "srcmac":
		TagSrcMac = t
	case "srcuser":
		TagSrcUser = t
	case "srcuid":
		TagSrcUid = t
	case "srcgroup":
		TagSrcGroup = t
	case "srcgid":
		TagSrcGid = t
	case "srcemail":
		TagSrcEmail = t
	case "dstdomain":
		TagDstDomain = t
	case "dstzone":
		TagDstZone = t
	case "dsthost":
		TagDstHost = t
	case "dstip":
		TagDstIP = t
	case "dstipnat":
		TagDstIPNAT = t
	case "dstport":
		TagDstPort = t
	case "dstportnat":
		TagDstPortNAT = t
	case "dstmac":
		TagDstMac = t
	case "dstuser":
		TagDstUser = t
	case "dstuid":
		TagDstUid = t
	case "dstgroup":
		TagDstGroup = t
	case "dstgid":
		TagDstGid = t
	case "dstemail":
		TagDstEmail = t
	case "protocol":
		TagProtocol = t
	case "iniface":
		TagInIface = t
	case "outiface":
		TagOutIface = t
	case "policyid":
		TagPolicyID = t
	case "sessionid":
		TagSessionID = t
	case "object":
		TagObject = t
	case "action":
		TagAction = t
	case "command":
		TagCommand = t
	case "method":
		TagMethod = t
	case "status":
		TagStatus = t
	case "reason":
		TagReason = t
	case "bytesrecv":
		TagBytesRecv = t
	case "bytessent":
		TagBytesSent = t
	case "pktsrecv":
		TagPktsRecv = t
	case "pktssent":
		TagPktsSent = t
	case "duration":
		TagDuration = t
	}
}

var (
	TagUnknown    TagType = 0
	TagMsgId      TagType // The message identifier
	TagMsgTime    TagType // The timestamp that’s part of the log message
	TagSeverity   TagType // The severity of the event, e.g., Emergency, …
	TagPriority   TagType // The pirority of the event
	TagAppHost    TagType // The hostname of the host where the log message is generated
	TagAppIP      TagType // The IP address of the host where the application that generated the log message is running on.
	TagAppVendor  TagType // The type of application that generated the log message, e.g., Cisco, ISS
	TagAppName    TagType // The name of the application that generated the log message, e.g., asa, snort, sshd
	TagSrcDomain  TagType // The domain name of the initiator of the event, usually a Windows domain
	TagSrcZone    TagType // The originating zone
	TagSrcHost    TagType // The hostname of the originator of the event or connection.
	TagSrcIP      TagType // The IPv4 address of the originator of the event or connection.
	TagSrcIPNAT   TagType // The natted (network address translation) IP of the originator of the event or connection.
	TagSrcPort    TagType // The port number of the originating connection.
	TagSrcPortNAT TagType // The natted port number of the originating connection.
	TagSrcMac     TagType // The mac address of the host that originated the connection.
	TagSrcUser    TagType // The user that originated the session.
	TagSrcUid     TagType // The user id that originated the session.
	TagSrcGroup   TagType // The group that originated the session.
	TagSrcGid     TagType // The group id that originated the session.
	TagSrcEmail   TagType // The originating email address
	TagDstDomain  TagType // The domain name of the destination of the event, usually a Windows domain
	TagDstZone    TagType // The destination zone
	TagDstHost    TagType // The hostname of the destination of the event or connection.
	TagDstIP      TagType // The IPv4 address of the destination of the event or connection.
	TagDstIPNAT   TagType // The natted (network address translation) IP of the destination of the event or connection.
	TagDstPort    TagType // The destination port number of the connection.
	TagDstPortNAT TagType // The natted destination port number of the connection.
	TagDstMac     TagType // The mac address of the destination host.
	TagDstUser    TagType // The user at the destination.
	TagDstUid     TagType // The user id that originated the session.
	TagDstGroup   TagType // The group that originated the session.
	TagDstGid     TagType // The group id that originated the session.
	TagDstEmail   TagType // The destination email address
	TagProtocol   TagType // The protocol, such as TCP, UDP, ICMP, of the connection
	TagInIface    TagType // The incoming TagTypeerface
	TagOutIface   TagType // The outgoing TagTypeerface
	TagPolicyID   TagType // The policy ID
	TagSessionID  TagType // The session or process ID
	TagObject     TagType // The object affected.
	TagAction     TagType // The action taken
	TagCommand    TagType // The command executed
	TagMethod     TagType // The method in which the action was taken, for example, public key or password for ssh
	TagStatus     TagType // The status of the action taken
	TagReason     TagType // The reason for the action taken or the status returned
	TagBytesRecv  TagType // The number of bytes received
	TagBytesSent  TagType // The number of bytes sent
	TagPktsRecv   TagType // The number of packets received
	TagPktsSent   TagType // The number of packets sent
	TagDuration   TagType // The duration of the session
)
