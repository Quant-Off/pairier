package wire

const (
	KeyIDLen      = 16
	MaxLabel      = 256
	MaxName       = 64
	MaxKeyBlob    = 16 * 1024
	MaxPublicKey  = 8 * 1024
	MaxSignature  = 8 * 1024
	MaxAAD        = 64 * 1024
	MaxPlaintext  = 64 * 1024
	MaxCiphertext = MaxPlaintext + 64
	MaxMessage    = 64 * 1024
	MaxRandom     = 1024
	MaxContext    = 1024
	MaxPackage    = 8 * 1024
)

const (
	AlgAES256GCM          uint16 = 0x0001
	AlgECDSAP256SHA256    uint16 = 0x0010
	AlgECDSAP384SHA384    uint16 = 0x0011
	AlgEd25519            uint16 = 0x0020
	AlgDHKEMP256          uint16 = 0x0030
	AlgMLDSA65            uint16 = 0x0100
	AlgMLDSA87            uint16 = 0x0101
	AlgMLKEM768           uint16 = 0x0200
	AlgMLKEM1024          uint16 = 0x0201
	AlgHybridP256MLKEM768 uint16 = 0x0210
)

const (
	UsageEncrypt     uint32 = 1 << 0
	UsageDecrypt     uint32 = 1 << 1
	UsageSign        uint32 = 1 << 2
	UsageVerify      uint32 = 1 << 3
	UsageWrap        uint32 = 1 << 4
	UsageUnwrap      uint32 = 1 << 5
	UsageDerive      uint32 = 1 << 6
	UsageDecapsulate uint32 = 1 << 7
	UsageExport      uint32 = 1 << 8
	UsageAll         uint32 = (1 << 9) - 1
)

const (
	CapFIPS uint64 = 1 << 0
	CapPQC  uint64 = 1 << 1
)

type Message interface {
	Op() Op
	Encode(w *Writer)
	Decode(r *Reader) error
}

func EncodeBody(m Message) ([]byte, error) {
	w := NewWriter()
	m.Encode(w)
	return w.Finish()
}

func DecodeBody(m Message, body []byte) error {
	r := NewReader(body)
	if err := m.Decode(r); err != nil {
		return err
	}
	return r.Finish()
}

type HelloRequest struct {
	ProtocolVersion uint32
}

func (*HelloRequest) Op() Op { return OpHello }

func (m *HelloRequest) Encode(w *Writer) { w.U32(m.ProtocolVersion) }

func (m *HelloRequest) Decode(r *Reader) (err error) {
	m.ProtocolVersion, err = r.U32()
	return err
}

type HelloResponse struct {
	ProtocolVersion uint32
	Capabilities    uint64
	EngineName      string
	EngineVersion   string
}

func (*HelloResponse) Op() Op { return OpHello }

func (m *HelloResponse) Encode(w *Writer) {
	w.U32(m.ProtocolVersion)
	w.U64(m.Capabilities)
	w.String(m.EngineName)
	w.String(m.EngineVersion)
}

func (m *HelloResponse) Decode(r *Reader) (err error) {
	if m.ProtocolVersion, err = r.U32(); err != nil {
		return err
	}
	if m.Capabilities, err = r.U64(); err != nil {
		return err
	}
	if m.EngineName, err = r.String(MaxName); err != nil {
		return err
	}
	m.EngineVersion, err = r.String(MaxName)
	return err
}

type PingRequest struct{}

func (*PingRequest) Op() Op               { return OpPing }
func (*PingRequest) Encode(*Writer)       {}
func (*PingRequest) Decode(*Reader) error { return nil }

type PingResponse struct{}

func (*PingResponse) Op() Op               { return OpPing }
func (*PingResponse) Encode(*Writer)       {}
func (*PingResponse) Decode(*Reader) error { return nil }

type KeyGenerateRequest struct {
	Alg   uint16
	Usage uint32
	Label string
}

func (*KeyGenerateRequest) Op() Op { return OpKeyGenerate }

func (m *KeyGenerateRequest) Encode(w *Writer) {
	w.U16(m.Alg)
	w.U32(m.Usage)
	w.String(m.Label)
}

func (m *KeyGenerateRequest) Decode(r *Reader) (err error) {
	if m.Alg, err = r.U16(); err != nil {
		return err
	}
	if m.Usage, err = r.U32(); err != nil {
		return err
	}
	m.Label, err = r.String(MaxLabel)
	return err
}

type KeyGenerateResponse struct {
	KeyID     [KeyIDLen]byte
	KeyBlob   []byte
	PublicKey []byte
}

func (*KeyGenerateResponse) Op() Op { return OpKeyGenerate }

func (m *KeyGenerateResponse) Encode(w *Writer) {
	w.Bytes(m.KeyID[:])
	w.Bytes(m.KeyBlob)
	w.Bytes(m.PublicKey)
}

func (m *KeyGenerateResponse) Decode(r *Reader) (err error) {
	id, err := r.Array(KeyIDLen)
	if err != nil {
		return err
	}
	copy(m.KeyID[:], id)
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	m.PublicKey, err = r.Bytes(MaxPublicKey)
	return err
}

type AeadEncryptRequest struct {
	KeyBlob   []byte
	Plaintext []byte
	AAD       []byte
}

func (*AeadEncryptRequest) Op() Op { return OpAeadEncrypt }

func (m *AeadEncryptRequest) Encode(w *Writer) {
	w.Bytes(m.KeyBlob)
	w.Bytes(m.Plaintext)
	w.Bytes(m.AAD)
}

func (m *AeadEncryptRequest) Decode(r *Reader) (err error) {
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	if m.Plaintext, err = r.Bytes(MaxPlaintext); err != nil {
		return err
	}
	m.AAD, err = r.Bytes(MaxAAD)
	return err
}

type AeadEncryptResponse struct {
	Ciphertext []byte
}

func (*AeadEncryptResponse) Op() Op { return OpAeadEncrypt }

func (m *AeadEncryptResponse) Encode(w *Writer) { w.Bytes(m.Ciphertext) }

func (m *AeadEncryptResponse) Decode(r *Reader) (err error) {
	m.Ciphertext, err = r.Bytes(MaxCiphertext)
	return err
}

type AeadDecryptRequest struct {
	KeyBlob    []byte
	Ciphertext []byte
	AAD        []byte
}

func (*AeadDecryptRequest) Op() Op { return OpAeadDecrypt }

func (m *AeadDecryptRequest) Encode(w *Writer) {
	w.Bytes(m.KeyBlob)
	w.Bytes(m.Ciphertext)
	w.Bytes(m.AAD)
}

func (m *AeadDecryptRequest) Decode(r *Reader) (err error) {
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	if m.Ciphertext, err = r.Bytes(MaxCiphertext); err != nil {
		return err
	}
	m.AAD, err = r.Bytes(MaxAAD)
	return err
}

type AeadDecryptResponse struct {
	Plaintext []byte
}

func (*AeadDecryptResponse) Op() Op { return OpAeadDecrypt }

func (m *AeadDecryptResponse) Encode(w *Writer) { w.Bytes(m.Plaintext) }

func (m *AeadDecryptResponse) Decode(r *Reader) (err error) {
	m.Plaintext, err = r.Bytes(MaxPlaintext)
	return err
}

type SignRequest struct {
	KeyBlob []byte
	Message []byte
}

func (*SignRequest) Op() Op { return OpSign }

func (m *SignRequest) Encode(w *Writer) {
	w.Bytes(m.KeyBlob)
	w.Bytes(m.Message)
}

func (m *SignRequest) Decode(r *Reader) (err error) {
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	m.Message, err = r.Bytes(MaxMessage)
	return err
}

type SignResponse struct {
	Signature []byte
}

func (*SignResponse) Op() Op { return OpSign }

func (m *SignResponse) Encode(w *Writer) { w.Bytes(m.Signature) }

func (m *SignResponse) Decode(r *Reader) (err error) {
	m.Signature, err = r.Bytes(MaxSignature)
	return err
}

type VerifyRequest struct {
	Alg       uint16
	PublicKey []byte
	Message   []byte
	Signature []byte
}

func (*VerifyRequest) Op() Op { return OpVerify }

func (m *VerifyRequest) Encode(w *Writer) {
	w.U16(m.Alg)
	w.Bytes(m.PublicKey)
	w.Bytes(m.Message)
	w.Bytes(m.Signature)
}

func (m *VerifyRequest) Decode(r *Reader) (err error) {
	if m.Alg, err = r.U16(); err != nil {
		return err
	}
	if m.PublicKey, err = r.Bytes(MaxPublicKey); err != nil {
		return err
	}
	if m.Message, err = r.Bytes(MaxMessage); err != nil {
		return err
	}
	m.Signature, err = r.Bytes(MaxSignature)
	return err
}

type VerifyResponse struct {
	Valid bool
}

func (*VerifyResponse) Op() Op { return OpVerify }

func (m *VerifyResponse) Encode(w *Writer) { w.Bool(m.Valid) }

func (m *VerifyResponse) Decode(r *Reader) (err error) {
	m.Valid, err = r.Bool()
	return err
}

type RandomRequest struct {
	Len uint32
}

func (*RandomRequest) Op() Op { return OpRandom }

func (m *RandomRequest) Encode(w *Writer) { w.U32(m.Len) }

func (m *RandomRequest) Decode(r *Reader) (err error) {
	if m.Len, err = r.U32(); err != nil {
		return err
	}
	if m.Len > MaxRandom {
		return ErrTooLarge
	}
	return nil
}

type RandomResponse struct {
	Bytes []byte
}

func (*RandomResponse) Op() Op { return OpRandom }

func (m *RandomResponse) Encode(w *Writer) { w.Bytes(m.Bytes) }

func (m *RandomResponse) Decode(r *Reader) (err error) {
	m.Bytes, err = r.Bytes(MaxRandom)
	return err
}

type KeyInspectRequest struct {
	KeyBlob []byte
}

func (*KeyInspectRequest) Op() Op { return OpKeyInspect }

func (m *KeyInspectRequest) Encode(w *Writer) { w.Bytes(m.KeyBlob) }

func (m *KeyInspectRequest) Decode(r *Reader) (err error) {
	m.KeyBlob, err = r.Bytes(MaxKeyBlob)
	return err
}

type KeyInspectResponse struct {
	Alg       uint16
	Usage     uint32
	KeyID     [KeyIDLen]byte
	Label     string
	PublicKey []byte
}

func (*KeyInspectResponse) Op() Op { return OpKeyInspect }

func (m *KeyInspectResponse) Encode(w *Writer) {
	w.U16(m.Alg)
	w.U32(m.Usage)
	w.Bytes(m.KeyID[:])
	w.String(m.Label)
	w.Bytes(m.PublicKey)
}

func (m *KeyInspectResponse) Decode(r *Reader) (err error) {
	if m.Alg, err = r.U16(); err != nil {
		return err
	}
	if m.Usage, err = r.U32(); err != nil {
		return err
	}
	id, err := r.Array(KeyIDLen)
	if err != nil {
		return err
	}
	copy(m.KeyID[:], id)
	if m.Label, err = r.String(MaxLabel); err != nil {
		return err
	}
	m.PublicKey, err = r.Bytes(MaxPublicKey)
	return err
}

type KeyExportRequest struct {
	KeyBlob            []byte
	KemAlg             uint16
	RecipientPublicKey []byte
	Usage              uint32
	Context            []byte
}

func (*KeyExportRequest) Op() Op { return OpKeyExport }

func (m *KeyExportRequest) Encode(w *Writer) {
	w.Bytes(m.KeyBlob)
	w.U16(m.KemAlg)
	w.Bytes(m.RecipientPublicKey)
	w.U32(m.Usage)
	w.Bytes(m.Context)
}

func (m *KeyExportRequest) Decode(r *Reader) (err error) {
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	if m.KemAlg, err = r.U16(); err != nil {
		return err
	}
	if m.RecipientPublicKey, err = r.Bytes(MaxPublicKey); err != nil {
		return err
	}
	if m.Usage, err = r.U32(); err != nil {
		return err
	}
	m.Context, err = r.Bytes(MaxContext)
	return err
}

type KeyExportResponse struct {
	Package []byte
}

func (*KeyExportResponse) Op() Op { return OpKeyExport }

func (m *KeyExportResponse) Encode(w *Writer) { w.Bytes(m.Package) }

func (m *KeyExportResponse) Decode(r *Reader) (err error) {
	m.Package, err = r.Bytes(MaxPackage)
	return err
}

type KeyImportRequest struct {
	KemKeyBlob []byte
	Package    []byte
	Context    []byte
}

func (*KeyImportRequest) Op() Op { return OpKeyImport }

func (m *KeyImportRequest) Encode(w *Writer) {
	w.Bytes(m.KemKeyBlob)
	w.Bytes(m.Package)
	w.Bytes(m.Context)
}

func (m *KeyImportRequest) Decode(r *Reader) (err error) {
	if m.KemKeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	if m.Package, err = r.Bytes(MaxPackage); err != nil {
		return err
	}
	m.Context, err = r.Bytes(MaxContext)
	return err
}

type KeyImportResponse struct {
	KeyID   [KeyIDLen]byte
	KeyBlob []byte
	Alg     uint16
	Usage   uint32
	Label   string
}

func (*KeyImportResponse) Op() Op { return OpKeyImport }

func (m *KeyImportResponse) Encode(w *Writer) {
	w.Bytes(m.KeyID[:])
	w.Bytes(m.KeyBlob)
	w.U16(m.Alg)
	w.U32(m.Usage)
	w.String(m.Label)
}

func (m *KeyImportResponse) Decode(r *Reader) (err error) {
	id, err := r.Array(KeyIDLen)
	if err != nil {
		return err
	}
	copy(m.KeyID[:], id)
	if m.KeyBlob, err = r.Bytes(MaxKeyBlob); err != nil {
		return err
	}
	if m.Alg, err = r.U16(); err != nil {
		return err
	}
	if m.Usage, err = r.U32(); err != nil {
		return err
	}
	m.Label, err = r.String(MaxLabel)
	return err
}

func NewMessage(op Op, kind Kind) Message {
	switch kind {
	case KindRequest:
		switch op {
		case OpHello:
			return &HelloRequest{}
		case OpPing:
			return &PingRequest{}
		case OpKeyGenerate:
			return &KeyGenerateRequest{}
		case OpKeyInspect:
			return &KeyInspectRequest{}
		case OpKeyExport:
			return &KeyExportRequest{}
		case OpKeyImport:
			return &KeyImportRequest{}
		case OpAeadEncrypt:
			return &AeadEncryptRequest{}
		case OpAeadDecrypt:
			return &AeadDecryptRequest{}
		case OpSign:
			return &SignRequest{}
		case OpVerify:
			return &VerifyRequest{}
		case OpRandom:
			return &RandomRequest{}
		}
	case KindResponse:
		switch op {
		case OpHello:
			return &HelloResponse{}
		case OpPing:
			return &PingResponse{}
		case OpKeyGenerate:
			return &KeyGenerateResponse{}
		case OpKeyInspect:
			return &KeyInspectResponse{}
		case OpKeyExport:
			return &KeyExportResponse{}
		case OpKeyImport:
			return &KeyImportResponse{}
		case OpAeadEncrypt:
			return &AeadEncryptResponse{}
		case OpAeadDecrypt:
			return &AeadDecryptResponse{}
		case OpSign:
			return &SignResponse{}
		case OpVerify:
			return &VerifyResponse{}
		case OpRandom:
			return &RandomResponse{}
		}
	}
	return nil
}
