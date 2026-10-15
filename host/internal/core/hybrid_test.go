package core

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	hybridLabel = "MLKEM768-P256"
	exportInfo  = "pairier/kms/key-export/v1"
	aeadInfo    = "pairier/kms/aead/v1"

	hybridVectorSeed   = "dfa3a04d54a0ec2f7edec57185e3df94063855fc7af64f25b815417a2c6eb0e4"
	hybridVectorPublic = "ecab6a5f147046838ef641bf65f52fcce29e6130038573128e839a1ad7cb1a35a9c95c3a41d7464b365a3043b17a153c" +
		"6a09382c580fcec41f38940d336309636c775bb20461f9814be668deea4d07623f545241445b72bc15125c8b90a7c41c" +
		"da17292f93ab55659fdeab787340011e5c3de9e4a699660ff5256db96224b2586fecf6475fa76bc0978fd25b10996030" +
		"53f48023baa119074011e01ca3f92a09ca088c2a9af0697416e661eebc46a2069c31042c570678cc229f6e502121112f" +
		"4a148acc59990d6c378db26f97398bd2929a19d0c50b5713400b70f9d50c79388510c13bdf975f4b4c60f7fa643f059a" +
		"faa580b61975fd59aa98b4c5f2cac3422b9f89f73d14a18a15942a5567c4baa09359a45d1ed35177959bbfe196c7314f" +
		"95f0a40d24c6668b10de95a7e08cafb46873c99611bbdb8e1d5cb0c8c2beff0b41fae1000ec9cea1032a3a6838c36053" +
		"97d59fb28c9975aa5f958725598a0c82b788f7fa22dd741a0e673497617043374e47f69903c891f47787ad069132a93e" +
		"b6f9b15ff9923318a5c382c0fc7b432d8a00652197941684a9567a92515c71daa8daf80f2e425488f88bffea0ca2a6c6" +
		"82d8aa68264ef00241f0ba62e2d529add964129997f51a4a0d195b6d5b0c31634ae81cad7fa53442c76646a996b60c3e" +
		"5f1818fdfa1895c0aa8cf393f91baeef237861e48bbb236c3460b949800ae4c3255454582a04abc3777c94f3ba0f3a4b" +
		"4309024d117e5a3597e53a6655e17524805dbb4386af689609310f8c85c101bcbdca7c9fbec251a4f62e18b839bf46a1" +
		"da5034a8887683a2b56133b7909665c5a097b7f40be725131156396bd60ff6021f17672795a375eefc66ce667e2d861a" +
		"03242a2c67ab845301b2882cc62b54ba040a425611f8599744b741e55643bbeb0851b30ba7ca922d0078407396272355" +
		"ee3c08a91670f2b8488b3c9c8791778a000aa263a75322831468679f795578863e67e149ccab053b39497be4ca149133" +
		"a2e91cabc8390119900fda90d7b2413da2bcd9d244600178b7164446fb3a3dc433a415a8001085b45bbad32843835464" +
		"999717ef180f51fc8660e63b400c957c609dc2bb6e43326fb33ab6c6c66dfe78a70bf5394c9262d65a395f857989854b" +
		"95f99481d1862a5a3b5555ab9d44b1cb0bc9df89395b192bf4c43dde2bbb610850c6024c8591a7e6933746921421575d" +
		"703a45e2bc08f86376c2a1cb2d133cf0346ccaeaadb81929c2d6126091c06ca81f95e413507b91e0f0cf548a5e79c344" +
		"fd962c56c895238395abfa90bb27b7b646707120a894c3c947411ba11255f5a6a032cb3dbd06b80d1229e9dbcaa3fc84" +
		"fe65561c3c4a8333cb7d1b4df823466041123fb604c14349ff8bc4b02ba1de71303cb99cfb3649f16703cea12780688c" +
		"ab0529a4a8cf1b09b5ed705231964a74622718248be25234add881a02a7572cb5ded432ef95a078f626c0006a0a0cc4e" +
		"7992b08b52c552d80b1c71c3906b32ae52974b10447cf6ac6dc3a3dd53151611288dac5dddd98679b611d0c805d48aa5" +
		"069451a03c3e9e880228e581901a5cc45c34cfc1cd258a7f7a10b90c281dd3da315a0b3a5c9669f3640c27d33028f922" +
		"764585f8ae61cd138197f7f30615fcf00c2413dd168044c9a4e65e5f68e93f4b04edadc409f9fdbacde2f03203b08d8f" +
		"35d316fc7e0a2fc57799c2ca8332a514c58c4260f57f980a241a6f98942c92c8c90f33541460657dde1040a84055924a" +
		"69"
	hybridVectorEnc = "ed5b96e04d48095bed5a54589775ee4979362198c7727fdcd62fbd6d0d4552aa5ae2a30283049bcbde84dd6e4c8a330b" +
		"df9ccf04190fbde2c63c0c9026740d5d00750e4c6244ac0e7b6a6edb8782f0ac040b4161d3a9f6500ffd1cfe6e93298c" +
		"caae1dc04a6519f52d96e43c4e7477cbdefdd17b65e002e2b04d1f3d5715dfa3a0014faba0eee73a2f30d9a71dfa4ef9" +
		"a0a37ee45a7f67c9209efff17badd21d452bbae583b046a602614ffe168bdd8ec27048dc5d95f58f8b70134c16128281" +
		"6dffbf9f88db63f28b39ed958cae9b5ea26f0ee54927d1483b644f338be3cb6b20157fd4b91b4fa7266b32bacbd73e12" +
		"afe877181d0123f02212902b1eb436c0970c395355ce6d92568014da811cd369ac68cb3d4be48318a2072965358bf079" +
		"9f1320ee1a98268d8a5796c965bbc19d8b5ec7322e5390bd93aa85103e4dfbe35f16331afa21a128c62a0f9bdd04e321" +
		"d266187413263fdc40522ca665df0272ac2a0418b692148fc3c2aa9273aaf424f9ddff17fb714e40be0595e6f3cc2d4e" +
		"82732622ef545218ddbde8b902ff2df9150dd4a3d6af2300f57e9b72b6eccf95bfe26ced55081e01d4723a81abd0f00d" +
		"44a40020d85d9c7c73ad4b129f7ebbba4d6c57e6251c58e824b47624e2e2a78c734cf21e76f0d7faaceba8b7b1ad1d66" +
		"3d8edc09b20d475fe79c6947f6a56fa371bb0c80625ba85fe475812137e216709fe99bb1a8d63ea38b34c89c1bde2b86" +
		"85b146bf185537e53df86bae6dad3950fc946fd47893f48fdd1066a5fef1aeeb75144f0966717e12b092fd96a30503d7" +
		"ffb84d1125bfb6422f296c1ef82701e5cca93a79a440a4b29a9de5961b582237fb7d71e5380df2bb8861c5dc2c6bead3" +
		"ba60a35f6104bb50481e1436cac2828798011b9ba20a39017576be7a49559a3eb9b1212bfede28f72beffe5b40254df4" +
		"90ce0cbcc9110159d24cbe6b48227c5d0bc91c70d7f5204693122d06abee77b99fce86e12c51e6a460d5b47a0f19dfc5" +
		"e0b6fbdb454abd151efbea1bc514074405497308a7278da302e9f64b033f78df23a31ecf071bf1f9cb30d9a7ea1cc87d" +
		"d0066f3c1aaa0222caa580f8333ddffbdcb795da1869882ba55497b33ea610e38031de9923e1ef1f2cd48af494507a77" +
		"65c7e67734e81a4d3683823dc7d15e8364280f255b8bdc7972c6d5f1385d11ea8bd5d7225fc5987a3a6d65bcd20b5334" +
		"fb7036785950dda89bbcfd337ac286d87bf5447f3c7d16930a07995236970a65acb5c0cb56cb6294046296711b7bf3d7" +
		"c1d40d26efb9550a50d653cea6844caf567dde9e78786b91a21eca728ef80f4b066962edd50144f2a0e7f7a36934a6ad" +
		"42ccb51bfe75c66839af77456a126d71f09b40640fbc3eca319b16c525f422fefc83e4a2c9c2ae18f1c967a77660dc3a" +
		"cb57bc12e1f6692fdf1ee034fe8e0f5808143c4f342c5e6a37c520dc3a4c14e77ffe260e1027ec91bb4682417cfcd505" +
		"b5c45e01e1532e8925eeeaa48ab5fd80e28dad7034aab8afdf96c6234842aca004f0aced6022c4e2f067b928d4908de2" +
		"0aa3f2d14307bacc6ec685b026858d06f5e98da3f120d5e8ab830248c49c3c4a4f0830298100999cbae5419d5ef0e557" +
		"f0"
	hybridVectorShared = "3688931682c215e9e06ad620eba7faa70dd0d38081b4ea3d5b636ee062578991"
)

type hybridKey struct {
	pq *mlkem.DecapsulationKey768
	t  *ecdh.PrivateKey
}

func hybridFromSeed(seed []byte) (*hybridKey, error) {
	s := sha3.NewSHAKE256()
	s.Write(seed)
	seedPQ := make([]byte, mlkem.SeedSize)
	s.Read(seedPQ)
	pq, err := mlkem.NewDecapsulationKey768(seedPQ)
	if err != nil {
		return nil, err
	}
	seedT := make([]byte, 32)
	for {
		s.Read(seedT)
		if t, err := ecdh.P256().NewPrivateKey(seedT); err == nil {
			return &hybridKey{pq: pq, t: t}, nil
		}
	}
}

func (k *hybridKey) public() []byte {
	return append(k.pq.EncapsulationKey().Bytes(), k.t.PublicKey().Bytes()...)
}

func hybridCombine(ssPQ, ssT, ctT, pkT []byte) []byte {
	h := sha3.New256()
	h.Write(ssPQ)
	h.Write(ssT)
	h.Write(ctT)
	h.Write(pkT)
	h.Write([]byte(hybridLabel))
	return h.Sum(nil)
}

func (k *hybridKey) decap(ct []byte) ([]byte, error) {
	if len(ct) != mlkem.CiphertextSize768+65 {
		return nil, errors.New("invalid ciphertext size")
	}
	ssPQ, err := k.pq.Decapsulate(ct[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}
	ctT := ct[mlkem.CiphertextSize768:]
	pub, err := ecdh.P256().NewPublicKey(ctT)
	if err != nil {
		return nil, err
	}
	ssT, err := k.t.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return hybridCombine(ssPQ, ssT, ctT, k.t.PublicKey().Bytes()), nil
}

func hybridEncap(pk []byte) (ct, ss []byte, err error) {
	if len(pk) != mlkem.EncapsulationKeySize768+65 {
		return nil, nil, errors.New("invalid public key size")
	}
	ek, err := mlkem.NewEncapsulationKey768(pk[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, nil, err
	}
	pkT, err := ecdh.P256().NewPublicKey(pk[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return nil, nil, err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ssT, err := e.ECDH(pkT)
	if err != nil {
		return nil, nil, err
	}
	ssPQ, ctPQ := ek.Encapsulate()
	ctT := e.PublicKey().Bytes()
	return append(ctPQ, ctT...), hybridCombine(ssPQ, ssT, ctT, pkT.Bytes()), nil
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHybridReferenceMatchesVector(t *testing.T) {
	k, err := hybridFromSeed(unhex(t, hybridVectorSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.public(), unhex(t, hybridVectorPublic)) {
		t.Fatal("derived public key differs from the vector")
	}
	ss, err := k.decap(unhex(t, hybridVectorEnc))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, unhex(t, hybridVectorShared)) {
		t.Fatal("shared secret differs from the vector")
	}
	ct, ss2, err := hybridEncap(k.public())
	if err != nil {
		t.Fatal(err)
	}
	ss3, err := k.decap(ct)
	if err != nil || !bytes.Equal(ss2, ss3) {
		t.Fatalf("reference roundtrip: %v", err)
	}
}

func aeadFrom(t *testing.T, secret, salt []byte, info string) (cipher.AEAD, []byte) {
	t.Helper()
	okm, err := hkdf.Key(sha256.New, secret, salt, info, 32+12)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(okm[:32])
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return g, okm[32:]
}

func openCoreCiphertext(t *testing.T, key, ct, aad []byte) []byte {
	t.Helper()
	if len(ct) < 32 {
		t.Fatal("ciphertext too short")
	}
	g, nonce := aeadFrom(t, key, ct[:32], aeadInfo)
	pt, err := g.Open(nil, nonce, ct[32:], aad)
	if err != nil {
		t.Fatalf("open core ciphertext: %v", err)
	}
	return pt
}

func buildPackage(t *testing.T, keyID [16]byte, label string, usage uint32, ectx, enc, ss, secret []byte) []byte {
	t.Helper()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	w := wire.NewWriter()
	w.U8(1)
	w.U16(wire.AlgMLKEM768P256)
	w.U16(wire.AlgAES256GCM)
	w.U32(usage)
	w.Bytes(keyID[:])
	w.String(label)
	w.Bytes(ectx)
	w.Bytes(salt)
	w.Bytes(enc)
	aad, err := w.Finish()
	if err != nil {
		t.Fatal(err)
	}
	g, nonce := aeadFrom(t, ss, salt, exportInfo+string(keyID[:]))
	return append(aad, g.Seal(nil, nonce, secret, aad)...)
}

func openPackage(t *testing.T, k *hybridKey, pkg, ectx []byte) []byte {
	t.Helper()
	r := wire.NewReader(pkg)
	version, _ := r.U8()
	kemAlg, _ := r.U16()
	alg, _ := r.U16()
	_, _ = r.U32()
	keyID, _ := r.Array(16)
	_, _ = r.String(wire.MaxLabel)
	gotCtx, _ := r.Bytes(wire.MaxContext)
	salt, _ := r.Array(32)
	enc, err := r.Bytes(wire.MaxPublicKey)
	if err != nil || version != 1 || kemAlg != wire.AlgMLKEM768P256 || alg != wire.AlgAES256GCM || !bytes.Equal(gotCtx, ectx) {
		t.Fatalf("package header: version %d kem %#x alg %#x err %v", version, kemAlg, alg, err)
	}
	headerLen := len(pkg) - r.Remaining()
	ss, err := k.decap(enc)
	if err != nil {
		t.Fatal(err)
	}
	g, nonce := aeadFrom(t, ss, salt, exportInfo+string(keyID))
	secret, err := g.Open(nil, nonce, pkg[headerLen:], pkg[:headerLen])
	if err != nil {
		t.Fatalf("open package: %v", err)
	}
	return secret
}

func TestRealCoreHybridInterop(t *testing.T) {
	bin := realBinary(t)
	ctx := context.Background()
	c, err := Spawn(ctx, Options{Binary: bin, EphemeralRoot: true, PQC: true, AllowUnlockedMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.PQC() {
		t.Skip("core built without pqc")
	}
	ectx := []byte("interop-context")

	kem, err := c.GenerateKey(ctx, wire.AlgMLKEM768P256, wire.UsageDecapsulate, "core/kem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hpke.MLKEM768P256().NewPublicKey(kem.PublicKey); err != nil {
		t.Fatalf("stdlib rejects the core public key: %v", err)
	}
	enc, ss, err := hybridEncap(kem.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	var keyID [16]byte
	if _, err := rand.Read(keyID[:]); err != nil {
		t.Fatal(err)
	}
	pkg := buildPackage(t, keyID, "go/sent", wire.UsageEncrypt|wire.UsageDecrypt, ectx, enc, ss, secret)
	imp, err := c.ImportKey(ctx, kem.Blob, pkg, ectx)
	if err != nil {
		t.Fatalf("core rejects a package encapsulated by the reference: %v", err)
	}
	if imp.KeyID != keyID || imp.Label != "go/sent" {
		t.Fatalf("imported %+v", imp)
	}
	ct, err := c.Encrypt(ctx, imp.Blob, []byte("to go"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if pt := openCoreCiphertext(t, secret, ct, []byte("aad")); string(pt) != "to go" {
		t.Fatalf("plaintext %q", pt)
	}
	tampered := append([]byte{}, pkg...)
	tampered[len(pkg)-17-60] ^= 1
	if _, err := c.ImportKey(ctx, kem.Blob, tampered, ectx); err == nil {
		t.Fatal("tampered package accepted")
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	ref, err := hybridFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport, "core/shared")
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.ExportKey(ctx, k.Blob, wire.AlgMLKEM768P256, ref.public(), wire.UsageDecrypt, ectx)
	if err != nil {
		t.Fatal(err)
	}
	got := openPackage(t, ref, out, ectx)
	ct, err = c.Encrypt(ctx, k.Blob, []byte("from core"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt := openCoreCiphertext(t, got, ct, nil); string(pt) != "from core" {
		t.Fatalf("plaintext %q", pt)
	}
}
