package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Quant-Off/pairier/host/internal/auth"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/store"
)

const (
	maxInboxBody   = exchange.MaxEnvelope
	requestTimeout = 15 * time.Second
)

type Server struct {
	node *node.Node
	now  func() time.Time
}

func New(n *node.Node, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{node: n, now: now}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/card", s.card)
	mux.HandleFunc("POST /v1/inbox", s.inbox)
	return http.TimeoutHandler(secure(mux), requestTimeout, "timeout")
}

func (s *Server) TLSConfig() *tls.Config {
	return auth.ServerTLSConfig(s.node.TLSCertificate(), s.node, s.now)
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func (s *Server) peer(r *http.Request) (*exchange.Card, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	return auth.Peer(ctx, s.node, r.TLS, s.now())
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if _, err := s.peer(r); err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"member": s.node.MemberID(), "fips": s.node.FIPS(), "pqc": s.node.PQC()})
}

func (s *Server) card(w http.ResponseWriter, r *http.Request) {
	if _, err := s.peer(r); err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	_, raw, err := s.node.Card(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "card unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	peer, err := s.peer(r)
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.ContentLength > maxInboxBody {
		fail(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxInboxBody+1))
	if err != nil || len(raw) > maxInboxBody {
		fail(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}
	rec, err := s.node.StoreInbox(r.Context(), raw, peer.MemberID)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, map[string]string{"id": rec.ID})
	case errors.Is(err, store.ErrExists):
		fail(w, http.StatusConflict, "duplicate envelope")
	case errors.Is(err, node.ErrInboxFull):
		fail(w, http.StatusTooManyRequests, "inbox full for this sender")
	case errors.Is(err, node.ErrNotRecipient), errors.Is(err, node.ErrSenderMismatch), errors.Is(err, node.ErrUnknownMember),
		errors.Is(err, exchange.ErrFormat), errors.Is(err, exchange.ErrSignature),
		errors.Is(err, exchange.ErrBadMemberID), errors.Is(err, exchange.ErrAlgorithm),
		errors.Is(err, node.ErrSignatureAlg):
		fail(w, http.StatusBadRequest, "envelope rejected")
	default:
		fail(w, http.StatusInternalServerError, "inbox unavailable")
	}
}

type Client struct {
	node *node.Node
	now  func() time.Time
}

func NewClient(n *node.Node, now func() time.Time) *Client {
	if now == nil {
		now = time.Now
	}
	return &Client{node: n, now: now}
}

func (c *Client) httpClient(peer *exchange.Card) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   auth.ClientTLSConfig(c.node.TLSCertificate(), peer, c.now),
			ForceAttemptHTTP2: false,
			Proxy:             nil,
		},
	}
}

func (c *Client) Push(ctx context.Context, baseURL, to string, envelope []byte) (string, error) {
	peer, err := c.node.Member(ctx, to)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/inbox", bytes.NewReader(envelope))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	rsp, err := c.httpClient(peer).Do(req)
	if err != nil {
		return "", fmt.Errorf("api: push: %w", err)
	}
	defer rsp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(rsp.Body, 4096))
	if rsp.StatusCode != http.StatusCreated {
		var eb errorBody
		_ = json.Unmarshal(body, &eb)
		return "", fmt.Errorf("api: push rejected: %d %s", rsp.StatusCode, eb.Error)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !store.ValidKeyID(out.ID) {
		return "", errors.New("api: push: malformed response")
	}
	return out.ID, nil
}

func (c *Client) Health(ctx context.Context, baseURL, member string) error {
	peer, err := c.node.Member(ctx, member)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/health", nil)
	if err != nil {
		return err
	}
	rsp, err := c.httpClient(peer).Do(req)
	if err != nil {
		return fmt.Errorf("api: health: %w", err)
	}
	defer rsp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(rsp.Body, 4096))
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("api: health: status %d", rsp.StatusCode)
	}
	return nil
}
