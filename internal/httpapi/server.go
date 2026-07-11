package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/policy"
	"frp-control-server/internal/security"
)

type Server struct {
	mu     sync.RWMutex
	cfg    config.Config
	store  *db.Store
	policy policy.Engine
	dpi    *dpi.Service
	core   *frpcore.Manager
}

type Option func(*Server)

func WithDPIService(service *dpi.Service) Option {
	return func(s *Server) {
		s.dpi = service
	}
}

func WithFRPCore(core *frpcore.Manager) Option {
	return func(s *Server) {
		s.core = core
	}
}

func NewServer(cfg config.Config, store *db.Store, opts ...Option) *Server {
	server := &Server{
		cfg:    cfg,
		store:  store,
		policy: policy.NoopEngine{},
	}
	for _, opt := range opts {
		opt(server)
	}
	if server.dpi == nil {
		server.dpi = dpi.NewService(dpi.Options{})
	}
	if server.core == nil {
		server.core = frpcore.NewManager(server.dpi)
	}
	return server
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/system/bootstrap-state", s.bootstrapState)
	mux.HandleFunc("POST /api/v1/system/setup-admin", s.setupAdmin)
	mux.HandleFunc("POST /api/v1/system/setup", s.setupAdmin)
	mux.HandleFunc("POST /api/v1/system/repair-database", s.repairDatabase)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAdmin(s.me))

	mux.HandleFunc("GET /api/v1/admin/users", s.requireAdmin(s.listUsers))
	mux.HandleFunc("POST /api/v1/admin/users", s.requireAdmin(s.createUser))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}", s.requireAdmin(s.deleteUser))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/ban", s.requireAdmin(s.banUser))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/unban", s.requireAdmin(s.unbanUser))
	mux.HandleFunc("GET /api/v1/admin/user-policies", s.requireAdmin(s.listUserPolicies))
	mux.HandleFunc("GET /api/v1/admin/users/{id}/policy", s.requireAdmin(s.getUserPolicy))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}/policy", s.requireAdmin(s.updateUserPolicy))
	mux.HandleFunc("GET /api/v1/admin/dpi-policies", s.requireAdmin(s.listDPIPolicies))
	mux.HandleFunc("GET /api/v1/admin/dpi-events", s.requireAdmin(s.listDPIEvents))
	mux.HandleFunc("GET /api/v1/admin/users/{id}/dpi-policy", s.requireAdmin(s.getUserDPIPolicy))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}/dpi-policy", s.requireAdmin(s.updateUserDPIPolicy))

	mux.HandleFunc("GET /api/v1/admin/tokens", s.requireAdmin(s.listTokens))
	mux.HandleFunc("POST /api/v1/admin/tokens", s.requireAdmin(s.createToken))
	mux.HandleFunc("POST /api/v1/admin/tokens/{id}/rotate", s.requireAdmin(s.rotateToken))
	mux.HandleFunc("POST /api/v1/admin/tokens/{id}/ban", s.requireAdmin(s.banToken))
	mux.HandleFunc("POST /api/v1/admin/tokens/{id}/unban", s.requireAdmin(s.unbanToken))
	mux.HandleFunc("GET /api/v1/admin/tokens/{id}/grants", s.requireAdmin(s.listGrants))
	mux.HandleFunc("POST /api/v1/admin/tokens/{id}/grants", s.requireAdmin(s.createGrant))
	mux.HandleFunc("GET /api/v1/admin/clients", s.requireAdmin(s.listClients))
	mux.HandleFunc("GET /api/v1/admin/connected-clients", s.requireAdmin(s.listConnectedClients))
	mux.HandleFunc("DELETE /api/v1/admin/clients/{id}", s.requireAdmin(s.deleteClient))
	mux.HandleFunc("POST /api/v1/admin/clients/{id}/ban", s.requireAdmin(s.banClient))
	mux.HandleFunc("POST /api/v1/admin/clients/{id}/unban", s.requireAdmin(s.unbanClient))
	mux.HandleFunc("POST /api/v1/admin/clients/{id}/commands", s.requireAdmin(s.enqueueClientCommand))
	mux.HandleFunc("GET /api/v1/admin/connections", s.requireAdmin(s.listConnections))
	mux.HandleFunc("POST /api/v1/admin/connections/{id}/disconnect", s.requireAdmin(s.disconnectConnection))
	mux.HandleFunc("POST /api/v1/admin/blocked-ips", s.requireAdmin(s.blockInboundIP))
	mux.HandleFunc("DELETE /api/v1/admin/blocked-ips/{ip}", s.requireAdmin(s.unblockInboundIP))
	mux.HandleFunc("GET /api/v1/admin/system-settings", s.requireAdmin(s.getSystemSettings))
	mux.HandleFunc("PUT /api/v1/admin/system-settings", s.requireAdmin(s.updateSystemSettings))

	mux.HandleFunc("POST /api/v1/client/bootstrap", s.clientBootstrap)
	mux.HandleFunc("POST /api/v1/client/resource-policy", s.clientResourcePolicy)
	mux.HandleFunc("POST /api/v1/client/heartbeat", s.clientHeartbeat)
	mux.HandleFunc("POST /api/v1/client/logout", s.clientLogout)
	mux.HandleFunc("POST /api/v1/frp/plugin", s.frpPlugin)

	return s.withCommonHeaders(mux)
}

const (
	clientHeartbeatInterval = 10 * time.Second
	clientHeartbeatTimeout  = 60 * time.Second
)

func (s *Server) StartClientHeartbeatWatchdog(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(clientHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.enforceClientHeartbeatTimeout(ctx); err != nil {
					log.Printf("client heartbeat watchdog: %v", err)
				}
			}
		}
	}()
}

func (s *Server) enforceClientHeartbeatTimeout(ctx context.Context) error {
	store := s.getStore()
	if store == nil {
		return nil
	}
	clients, err := store.ListClientsWithStaleHeartbeat(ctx, int(clientHeartbeatTimeout.Seconds()))
	if err != nil {
		return err
	}
	for _, client := range clients {
		terminated := s.terminateClientRuntime(ctx, client, "client heartbeat timeout")
		deletedCommands, err := store.DeleteQueuedClientCommands(ctx, client.ID)
		if err != nil {
			return err
		}
		if err := store.ClearClientPresence(ctx, client.ID); err != nil {
			return err
		}
		store.Audit(ctx, "system", 0, "client_heartbeat_timeout", "client", strconv.FormatInt(client.ID, 10), fmt.Sprintf("terminated=%d deleted_commands=%d cleared_presence=true", terminated, deletedCommands))
	}
	return nil
}

func (s *Server) terminateClientRuntime(ctx context.Context, client db.Client, reason string) int {
	if store := s.getStore(); store != nil {
		_, _ = store.RevokeActiveRuntimeLeasesForClient(ctx, client.TokenID, client.ClientID, reason)
	}
	if s.core != nil {
		return s.core.TerminateConnectionsForClient(client.TokenID, client.ClientID)
	}
	return 0
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	response := map[string]any{"ok": true, "database_ready": s.getStore() != nil}
	if s.core != nil {
		response["frps"] = s.core.Status(cfg)
	}
	writeJSON(w, http.StatusOK, response)
}

type contextKey string

const userContextKey contextKey = "user"

const adminTokenCookieName = "frp_control_admin_token"

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store := s.getStore()
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "system setup required")
			return
		}
		tokenValue := bearerToken(r)
		if tokenValue == "" {
			cookie, err := r.Cookie(adminTokenCookieName)
			if err == nil {
				tokenValue = cookie.Value
			}
		}
		if tokenValue == "" {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		userID, err := security.AdminBrowserTokenUserID(tokenValue)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		user, err := store.GetUserByID(r.Context(), userID)
		if err != nil || user.Role != "admin" || user.Status != "active" {
			writeError(w, http.StatusForbidden, "admin required")
			return
		}
		adminToken, err := store.GetAdminAPITokenByUserID(r.Context(), userID)
		if err != nil || adminToken.Status != "active" {
			writeError(w, http.StatusForbidden, "admin token required")
			return
		}
		if _, _, err := security.ParseAdminBrowserToken(tokenValue, adminToken.TokenHash, s.getConfig().CookieSecret); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), userContextKey, user))
		next(w, r)
	}
}

func (s *Server) getConfig() config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Server) getStore() *db.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store
}

func (s *Server) setRuntime(cfg config.Config, store *db.Store) {
	s.mu.Lock()
	old := s.store
	s.cfg = cfg
	s.store = store
	s.mu.Unlock()
	if s.dpi != nil && store != nil {
		s.dpi.SetPolicyProvider(store)
		s.dpi.SetEventSink(store)
	}
	if old != nil && old != store {
		_ = old.Close()
	}
}

func currentUser(r *http.Request) *db.User {
	user, _ := r.Context().Value(userContextKey).(*db.User)
	return user
}

func readJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": message})
}

func parseID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func normalizeProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "tcp", "udp", "http", "https", "stcp", "xtcp", "tcpmux":
		return value
	default:
		return ""
	}
}

func validateAdminPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return ""
	}
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

func setAdminTokenCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminTokenCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func clearAdminTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminTokenCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "frp_control_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}
