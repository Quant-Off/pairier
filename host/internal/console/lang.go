package console

import (
	"fmt"
	"os"
	"strings"

	"github.com/Quant-Off/pairier/host/internal/tui"
)

const (
	LangEnglish = "en"
	LangKorean  = "ko"
	labelWidth  = 13
	detailWidth = 10
)

func Language(choice string) (string, error) {
	switch choice {
	case LangEnglish, LangKorean:
		return choice, nil
	case "", "auto":
	default:
		return "", fmt.Errorf("unknown language %q, use auto, en or ko", choice)
	}
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(name); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ko") {
				return LangKorean, nil
			}
			return LangEnglish, nil
		}
	}
	if systemKorean() {
		return LangKorean, nil
	}
	return LangEnglish, nil
}

func (a *app) t(s string) string {
	if v, ok := a.catalog[s]; ok {
		return v
	}
	return s
}

func (a *app) tf(format string, args ...any) string {
	return fmt.Sprintf(a.t(format), args...)
}

func pad(s string, w int) string {
	return s + strings.Repeat(" ", max(w-tui.StringWidth(s), 1))
}

func (a *app) kv(label, value string) string { return pad(a.t(label), labelWidth) + value }

func (a *app) dkv(label, value string) string { return pad(a.t(label), detailWidth) + value }

func (a *app) fpLines(fp string) []string {
	label := pad(a.t("fingerprint"), labelWidth)
	indent := strings.Repeat(" ", tui.StringWidth(label))
	var out []string
	for i, part := range splitFingerprint(fp) {
		if i == 0 {
			out = append(out, label+part)
		} else {
			out = append(out, indent+part)
		}
	}
	return out
}

var koreanTexts = tui.Texts{
	FormHint:     " Tab 이동  Space 선택  Enter 다음  Esc 취소 ",
	Close:        " Enter/Esc 닫기 ",
	Confirm:      " y 확인  n/Esc 취소 ",
	ConfirmTyped: " Enter 확인  Esc 취소 ",
	More:         " 위/아래 더 보기 ",
	Yes:          "[x] 예",
	No:           "[ ] 아니요",
	None:         "(없음)",
	Mismatch:     "입력한 내용이 일치하지 않습니다",
	Type:         "%s 입력: ",
}

var korean = map[string]string{
	"Node":    "노드",
	"Keys":    "키",
	"Members": "구성원",
	"Inbox":   "수신함",
	"Audit":   "감사",
	"Log":     "로그",

	"busy with %s":                                "%s 진행 중",
	"%s cancelled":                                "%s 취소됨",
	"%s failed: %s":                               "%s 실패: %s",
	"%s failed":                                   "%s 실패",
	"node closed after %s without input":          "입력 없이 %s이 지나 노드를 닫음",
	"node closed after inactivity":                "입력이 없어 노드를 닫았습니다",
	"terminal too small (%dx%d), need %dx%d":      "터미널이 너무 작습니다 (%dx%d), %dx%d 이상 필요",
	"resize the window or press Ctrl+C to quit":   "창을 키우거나 Ctrl+C로 끝내세요",
	"opening %s ...":                              "%s 여는 중 ...",
	"The node was closed after %s without input.": "입력 없이 %s이 지나 노드를 닫았습니다.",
	"The core process has exited and its key material is gone from memory.": "코어 프로세스가 끝났고 키 자료는 메모리에서 지워졌습니다.",
	"Enter reopen   q quit": "Enter 다시 열기   q 종료",
	"member":                "구성원",
	"[offline]":             "[오프라인]",
	"? help  q quit ":       "? 도움말  q 종료 ",
	"  Tab/1-6 tabs  / filter  Ctrl+R refresh":                    "  Tab/1-6 탭  / 필터  Ctrl+R 새로 고침",
	" ... (Esc cancels)":                                          " ... (Esc 취소)",
	" o open a node directory   n initialize a new node   q quit": " o 노드 디렉토리 열기   n 새 노드 초기화   q 종료",
	" Enter reopen   q quit":                                      " Enter 다시 열기   q 종료",
	" Esc cancel   q quit":                                        " Esc 취소   q 종료",
	" c export card  R renew card":                                " c 카드 내보내기  R 카드 갱신",
	" n new  s send":                                              " n 생성  s 보내기",
	"  p push":                                                    "  p push",
	"  r receive  e/d encrypt/decrypt  Enter info":                "  r 받기  e/d 암호화/복호화  Enter 정보",
	" a add  w witness heads":                                     " a 추가  w 증인 head",
	"  h health":                                                  "  h health",
	" Enter accept  x reject  i import file":                      " Enter 수락  x 거절  i 파일 가져오기",
	" v verify":                                                   " v 검증",
	" Up/Down scroll":                                             " 위/아래 스크롤",
	"No node is open.":                                            "열린 노드가 없습니다.",
	"o  open an existing node directory":                          "o  기존 노드 디렉토리 열기",
	"n  initialize a new node":                                    "n  새 노드 초기화",
	"q  quit":                                                     "q  종료",
	"Every action runs through the same node code as the kmsctl commands": "모든 동작은 kmsctl 명령과 같은 노드 코드로 실행되며",
	"and is written to the node audit log.":                               "노드 감사 로그에 기록됩니다.",

	"KEY ID":                    "키 ID",
	"ALG":                       "알고리즘",
	"USAGE":                     "용도",
	"LABEL":                     "라벨",
	"FROM":                      "출처",
	"local":                     "로컬",
	"MEMBER":                    "구성원",
	"IDENTITY":                  "신원",
	"KEM":                       "KEM",
	"FINGERPRINT":               "지문",
	"error":                     "오류",
	"ENVELOPE":                  "봉투",
	"SENT":                      "보낸 시각",
	"RECEIVED":                  "받은 시각",
	"SEQ":                       "순번",
	"TIME":                      "시각",
	"EVENT":                     "이벤트",
	"FIELDS":                    "필드",
	"SESSION LOG (memory only)": "세션 로그 (메모리에만 보관)",
	"(empty)":                   "(비어 있음)",
	"(nothing matches the filter %s, Esc clears it)": "(필터 %s에 맞는 항목이 없습니다, Esc로 지우기)",
	"filter: %s":               "필터: %s",
	"generated on this node":   "이 노드에서 생성",
	"from %s sent %s":          "%s에게서, 보낸 시각 %s",
	"id":                       "id",
	"label":                    "라벨",
	"usage":                    "용도",
	"created":                  "생성",
	"origin":                   "출처",
	"fingerprint":              "지문",
	"witnessed audit heads %d": "증인으로 본 감사 head %d개",
	", latest %s":              ", 최근 %s",
	"warning the card uses a retired kem, ask the member to run card renew": "경고 카드가 폐기된 KEM을 씁니다. 구성원에게 card renew를 요청하세요",
	"from":                    "보낸 이",
	"not a registered member": "등록되지 않은 구성원",
	"envelope":                "봉투",
	"sent":                    "보낸 시각",
	"received":                "받은 시각",
	"Enter verifies and imports the key, x deletes the envelope": "Enter는 검증 후 키를 가져오고, x는 봉투를 지웁니다",
	"Member":                               "구성원",
	"Directory":                            "디렉토리",
	"Fingerprint":                          "지문",
	"Identity":                             "신원",
	"  retired, press R to renew the card": "  폐기됨, R로 카드를 갱신하세요",
	"held in the core":                     "코어 안에 보관",
	"stored outside the core, press R to renew the card": "코어 밖에 저장됨, R로 카드를 갱신하세요",
	"TLS key":   "TLS 키",
	"Core":      "코어",
	"Host":      "호스트",
	"Audit log": "감사 로그",
	"Store":     "저장소",
	"%d keys, %d members, %d pending envelopes":                                   "키 %d개, 구성원 %d명, 대기 봉투 %d개",
	"network actions enabled (push, health, peer audit), each needs an https URL": "네트워크 동작 사용(push, health, 상대 노드 감사), 각각 https URL 필요",
	"offline, actions that contact other nodes are hidden":                        "오프라인, 다른 노드에 접속하는 동작은 숨김",
	"Mode":       "모드",
	"Idle close": "유휴 종료",
	"Not verified in this session. Press v to verify the chain, anchors and witnessed heads.": "이 세션에서 아직 검증하지 않았습니다. v를 눌러 체인, anchor, 증인 head를 검증하세요.",
	"Verification FAILED at %s":                      "%s 검증 실패",
	", heads witnessed by %s":                        ", %s의 증인 head 포함",
	"Verified %d entries against %d anchors%s at %s": "%[4]s 검증 완료, 항목 %[1]d개, anchor %[2]d개%[3]s",
	"head":                       "head",
	"reading the log failed: %s": "로그 읽기 실패: %s",
	"seq %d   %s   %s":           "순번 %d   %s   %s",
	"Quit":                       "종료",
	"%s is still running. Quit anyway? The operation is cancelled.":                                                               "%s 작업이 아직 진행 중입니다. 그래도 끝낼까요? 작업은 취소됩니다.",
	"Tab, Shift+Tab or 1-6 switch tabs. Up/Down or j/k move, PgUp/PgDn and Home/End jump.":                                        "Tab, Shift+Tab, 1-6으로 탭을 바꿉니다. 위/아래나 j/k로 이동하고, PgUp/PgDn과 Home/End로 건너뜁니다.",
	"/ filters the list, Esc clears the filter or cancels a running action, Ctrl+R refreshes, Ctrl+L redraws, q or Ctrl+C quits.": "/는 목록을 거르고, Esc는 필터를 지우거나 실행 중인 동작을 취소하며, Ctrl+R은 새로 고침, Ctrl+L은 다시 그리기, q나 Ctrl+C는 종료입니다.",
	"Node     c export card (card)   R renew card (card renew)":                                                                   "노드     c 카드 내보내기 (card)   R 카드 갱신 (card renew)",
	"Keys     Enter info (key info)   n new (key gen)   s send to file (key send)   r receive file (key receive)":                 "키       Enter 정보 (key info)   n 생성 (key gen)   s 파일로 보내기 (key send)   r 파일 받기 (key receive)",
	"         e encrypt file (encrypt)   d decrypt file (decrypt)   p push to kmsd (key push)":                                    "         e 파일 암호화 (encrypt)   d 파일 복호화 (decrypt)   p kmsd로 push (key push)",
	"Members  a add card (member add)   w export witnessed heads (member witness)   h health (peer health)":                       "구성원   a 카드 추가 (member add)   w 증인 head 내보내기 (member witness)   h health (peer health)",
	"Inbox    Enter accept (inbox accept)   x reject (inbox reject)   i import envelope file (key receive)":                       "수신함   Enter 수락 (inbox accept)   x 거절 (inbox reject)   i 봉투 파일 가져오기 (key receive)",
	"Audit    v verify with anchors, an anchor file or a peer (audit verify)":                                                     "감사     v anchor, anchor 파일, 상대 노드로 검증 (audit verify)",
	"Fingerprints are never filled in for you, type them from the other channel.":                                                 "지문은 대신 채워 주지 않습니다. 다른 채널로 받은 지문을 직접 입력하세요.",
	"Decrypted data only goes to new files created for your user. Nothing is copied to the clipboard.":                            "복호화한 데이터는 본인만 읽을 수 있는 새 파일에만 씁니다. 클립보드에는 아무것도 복사하지 않습니다.",
	"Offline mode hides push, health and peer audit.":                                                                             "오프라인 모드에서는 push, health, 상대 노드 감사를 숨깁니다.",
	"Shortcuts also work while the Korean input method is on.":                                                                    "한글 입력 상태에서도 단축키가 동작합니다.",
	"Help": "도움말",

	"an input file is required":                "입력 파일이 필요합니다",
	"%s is not a regular file":                 "%s은(는) 일반 파일이 아닙니다",
	"%s exceeds %d bytes":                      "%s이(가) %d바이트를 넘습니다",
	"an output file is required":               "출력 파일이 필요합니다",
	"%s already exists, choose another name":   "%s이(가) 이미 있습니다. 다른 이름을 고르세요",
	"the url must use https":                   "URL은 https를 써야 합니다",
	"the url must look like https://HOST:PORT": "URL은 https://HOST:PORT 형식이어야 합니다",
	"choose at least one usage":                "용도를 하나 이상 고르세요",
	"opened %s as %s":                          "%s을(를) %s(으)로 열었습니다",
	"open node":                                "노드 열기",
	"Open node":                                "노드 열기",
	"Enter the node directory. If it does not exist yet you can initialize it next.": "노드 디렉토리를 입력하세요. 아직 없으면 이어서 초기화할 수 있습니다.",
	"a directory is required": "디렉토리가 필요합니다",
	"Member ID":               "구성원 ID",
	"Post-quantum":            "양자 내성",
	"lowercase letters, digits, . _ -, the name members know you by":                            "소문자, 숫자, . _ -, 다른 구성원이 알아보는 이름",
	"ML-DSA identity and ML-KEM exchange, needs a core built with pqc":                          "ML-DSA 신원과 ML-KEM 교환, pqc로 빌드한 코어가 필요합니다",
	"Creates the directory for your user only, a root key and the node identity (kmsctl init).": "본인만 쓸 수 있는 디렉토리와 루트 키, 노드 신원을 만듭니다 (kmsctl init).",
	"Initialize node":   "노드 초기화",
	"invalid member id": "잘못된 구성원 id입니다",
	"initialize node":   "노드 초기화",
	"identity":          "신원",
	"kem":               "KEM",
	"core_fips":         "core_fips",
	"Export your card with c and give the card and this fingerprint to each member over separate channels.": "c로 카드를 내보내고, 카드와 이 지문을 각 구성원에게 서로 다른 채널로 전달하세요.",
	"Node initialized":   "노드를 초기화했습니다",
	"Filter %s":          "%s 필터",
	"Contains":           "포함 문자열",
	"Export card":        "카드 내보내기",
	"Output file":        "출력 파일",
	"export card":        "카드 내보내기",
	"card written to %s": "카드를 %s에 썼습니다",
	"file":               "파일",
	"Send the card file and read the fingerprint to the member over a different channel.": "카드 파일을 보내고, 지문은 다른 채널로 구성원에게 읽어 주세요.",
	"Card exported": "카드를 내보냈습니다",
	"Renewing replaces the node KEM key, moves the TLS key into the core and signs a new card.":  "갱신하면 노드 KEM 키를 바꾸고, TLS 키를 코어 안으로 옮기고, 새 카드에 서명합니다.",
	"Every member has to add the new card with its new fingerprint, and kmsd must be restarted.": "모든 구성원이 새 카드를 새 지문으로 다시 추가해야 하고, kmsd를 다시 시작해야 합니다.",
	"Renew card":                       "카드 갱신",
	"renew card":                       "카드 갱신",
	"card renewed, new fingerprint %s": "카드를 갱신했습니다, 새 지문 %s",
	"New fingerprint %s":               "새 지문 %s",
	"Send the new card to every member and restart kmsd. Esc skips, c exports the card later.": "새 카드를 모든 구성원에게 보내고 kmsd를 다시 시작하세요. Esc로 건너뛰면 나중에 c로 내보낼 수 있습니다.",
	"Label": "라벨",
	"Usage": "용도",
	"export is needed to send the key to members": "구성원에게 보내려면 export가 필요합니다",
	"Generate key": "키 생성",
	"Creates an AES-256-GCM key inside the core (key gen).": "코어 안에서 AES-256-GCM 키를 만듭니다 (key gen).",
	"generate key":    "키 생성",
	"generated %s %s": "생성했습니다 %s %s",
	"alg":             "알고리즘",
	"%s   sent %s":    "%s   보낸 시각 %s",
	"key info":        "키 정보",
	"Key":             "키",
	"The stored metadata matches what the core reports for this key.": "저장된 메타데이터가 코어가 이 키에 대해 알려 주는 값과 일치합니다.",
	"No members": "구성원 없음",
	"Add the recipient on the Members tab first.": "먼저 구성원 탭에서 받는 이를 추가하세요.",
	"Recipient":                            "받는 이",
	"Grant":                                "부여 용도",
	"Left/Right picks a registered member": "Left/Right로 등록된 구성원을 고릅니다",
	"only a subset of this key's usage can be granted": "이 키 용도의 일부만 부여할 수 있습니다",
	"Send key to file": "파일로 키 보내기",
	"send key":         "키 보내기",
	"Seals the key for one member into an envelope file (key send).": "한 구성원만 열 수 있게 키를 봉투 파일로 봉인합니다 (key send).",
	"kmsd URL": "kmsd URL",
	"Push key": "키 push",
	"push key": "키 push",
	"Seals the key and delivers it to the member's kmsd over mutual TLS (key push).": "키를 봉인해 상호 TLS로 구성원의 kmsd에 전달합니다 (key push).",
	"unknown":   "알 수 없음",
	"key":       "키",
	"recipient": "받는 이",
	"grant":     "부여 용도",
	"kmsd":      "kmsd",
	"The recipient can use the key with this usage from now on. Continue?": "이제부터 받는 이가 이 용도로 키를 쓸 수 있습니다. 계속할까요?",
	"sent %s to %s in %s": "%[1]s을(를) %[2]s에게 보냈습니다, 파일 %[3]s",
	"Envelope written":    "봉투를 썼습니다",
	"Deliver it to %s, who imports it with r on the Keys tab or key receive.": "%s에게 전달하세요. 받는 쪽은 키 탭의 r이나 key receive로 가져옵니다.",
	"pushed %s to %s, envelope %s":                                            "%[1]s을(를) %[2]s에게 push했습니다, 봉투 %[3]s",
	"Key pushed":                                                              "키를 push했습니다",
	"%s accepts it from the Inbox tab or with inbox accept.":                  "%s이(가) 수신함 탭이나 inbox accept로 수락합니다.",
	"Decrypt file":                                                            "파일 복호화",
	"empty means the input name without .enc, or with .dec":                   "비우면 입력 이름에서 .enc를 빼거나 .dec를 붙입니다",
	"decrypt": "복호화",
	"The plaintext is written only to a new file that only your user can read. It is never shown.": "평문은 본인만 읽을 수 있는 새 파일에만 쓰고 화면에는 보여 주지 않습니다.",
	"Encrypt file":                         "파일 암호화",
	"empty means the input name with .enc": "비우면 입력 이름에 .enc를 붙입니다",
	"encrypt":                              "암호화",
	"Encrypts up to 1 MiB with AES-256-GCM inside the core.": "코어 안에서 1 MiB까지 AES-256-GCM으로 암호화합니다.",
	"Input file": "입력 파일",
	"AAD":        "AAD",
	"associated data, must be the same for encrypt and decrypt": "연관 데이터, 암호화와 복호화에서 같아야 합니다",
	"%s with %s":           "%s (%s)",
	"wrote %d bytes to %s": "%[2]s에 %[1]d바이트를 썼습니다",
	"Envelope file":        "봉투 파일",
	"Imports a key sent to this node after checking the signature, recipient and context (key receive).": "서명, 받는 이, 문맥을 확인한 뒤 이 노드로 보낸 키를 가져옵니다 (key receive).",
	"Receive key":         "키 받기",
	"receive key":         "키 받기",
	"received %s from %s": "%[2]s에게서 %[1]s을(를) 받았습니다",
	"Key received":        "키를 받았습니다",
	"Card file":           "카드 파일",
	"as the member read it to you, never copied from the card file":                     "구성원이 읽어 준 그대로, 카드 파일에서 복사하지 마세요",
	"Registers or updates a member (member add). Type or paste the fingerprint you got": "구성원을 등록하거나 갱신합니다 (member add). 직접 만나거나 전화처럼 별도 채널로",
	"over a separate channel, in person or by phone. It must match the card exactly.":   "받은 지문을 입력하거나 붙여 넣으세요. 카드와 정확히 일치해야 합니다.",
	"Add member":                   "구성원 추가",
	"the fingerprint is required":  "지문이 필요합니다",
	"add member":                   "구성원 추가",
	"Member added":                 "구성원을 추가했습니다",
	"added member %s":              "구성원 %s을(를) 추가했습니다",
	"Member updated":               "구성원을 갱신했습니다",
	"updated member %s":            "구성원 %s을(를) 갱신했습니다",
	"Export witnessed heads of %s": "%s의 증인 head 내보내기",
	"Writes the audit heads this node saw from the member, one SEQ:HASH per line (member witness).": "이 노드가 그 구성원에게서 본 감사 head를 한 줄에 하나씩 SEQ:HASH로 씁니다 (member witness).",
	"export witnessed heads":                "증인 head 내보내기",
	"wrote %d witnessed heads for %s to %s": "%[2]s의 증인 head %[1]d개를 %[3]s에 썼습니다",
	"Witnessed heads":                       "증인 head",
	"%d heads written to %s":                "head %d개를 %s에 썼습니다",
	"The member verifies its log with them on the Audit tab or audit verify --anchor-file.": "그 구성원은 감사 탭이나 audit verify --anchor-file로 자기 로그를 검증합니다.",
	"Health of %s": "%s health 확인",
	"Connects to the member's kmsd with mutual TLS pinned to its card (peer health).": "카드에 고정한 상호 TLS로 구성원의 kmsd에 접속합니다 (peer health).",
	"peer health":        "peer health",
	"health ok %s at %s": "health 정상 %s (%s)",
	"not a registered member, accepting will fail": "등록되지 않은 구성원이라 수락에 실패합니다",
	"Accept envelope": "봉투 수락",
	"The key is imported only if the signature, recipient and context verify. Accept?": "서명, 받는 이, 문맥이 모두 검증될 때만 키를 가져옵니다. 수락할까요?",
	"accept envelope":     "봉투 수락",
	"accepted %s, key %s": "%s을(를) 수락했습니다, 키 %s",
	"Key imported":        "키를 가져왔습니다",
	"Reject envelope":     "봉투 거절",
	"The envelope is deleted. The sender has to send it again. Reject?": "봉투를 지웁니다. 보낸 이가 다시 보내야 합니다. 거절할까요?",
	"reject envelope": "봉투 거절",
	"rejected %s":     "%s을(를) 거절했습니다",
	"Anchors":         "anchor",
	"Anchor file":     "anchor 파일",
	"SEQ:HASH heads recorded out of band, separated by spaces": "별도로 기록한 SEQ:HASH head, 공백으로 구분",
	"one SEQ:HASH per line, for example a member witness file": "한 줄에 SEQ:HASH 하나, 예를 들어 구성원 증인 파일",
	"(none)":        "(없음)",
	"Peer":          "상대 노드",
	"Peer kmsd URL": "상대 kmsd URL",
	"a member whose kmsd returns the heads it witnessed":                                       "자기가 증인으로 본 head를 돌려주는 kmsd의 구성원",
	"Replays the hash chain and checkpoint signatures and checks every anchor (audit verify).": "해시 체인과 체크포인트 서명을 다시 계산하고 모든 anchor를 확인합니다 (audit verify).",
	"Verify audit log":                   "감사 로그 검증",
	"verify audit log":                   "감사 로그 검증",
	"audit verification failed":          "감사 로그 검증 실패",
	"Audit verification failed":          "감사 로그 검증 실패",
	"audit verified %d entries, head %s": "감사 로그 항목 %d개 검증, head %s",
	"Audit log verified":                 "감사 로그를 검증했습니다",
	"entries":                            "항목",
	"anchors":                            "anchor",
	"Record the head somewhere the node cannot change to catch a later rollback.": "나중의 롤백을 잡아내려면 이 head를 노드가 바꿀 수 없는 곳에 기록하세요.",
}
