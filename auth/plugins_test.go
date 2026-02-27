package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins"
	"github.com/captjt/go-auth/plugins/emailotp"
	"github.com/captjt/go-auth/plugins/magiclink"
	"github.com/captjt/go-auth/plugins/passkey"
	"github.com/captjt/go-auth/plugins/twofactor"
	"github.com/captjt/go-auth/plugins/username"
	"github.com/captjt/go-auth/storage/memory"
)

func TestUsernamePluginFlow(t *testing.T) {
	s := newPluginServer(t, plugins.Username(username.Options{}))
	h := s.Handler()

	recSignUp := httptest.NewRecorder()
	reqSignUp := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/username/sign-up", strings.NewReader(`{"email":"bob@example.com","username":"bob","password":"supersecure1","name":"Bob"}`))
	h.ServeHTTP(recSignUp, reqSignUp)
	if recSignUp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", recSignUp.Code, recSignUp.Body.String())
	}

	recAvail := httptest.NewRecorder()
	reqAvail := httptest.NewRequest(http.MethodGet, "/auth/v1/plugins/username/available?username=bob", nil)
	h.ServeHTTP(recAvail, reqAvail)
	if recAvail.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recAvail.Code)
	}
	if strings.Contains(recAvail.Body.String(), `"available":true`) {
		t.Fatalf("expected username to be unavailable")
	}
}

func TestMagicLinkPluginFlow(t *testing.T) {
	s := newPluginServer(t, plugins.MagicLink(magiclink.Options{ExposeTokenInResponse: true}))
	h := s.Handler()

	recRequest := httptest.NewRecorder()
	reqRequest := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/magic-link/request", strings.NewReader(`{"email":"maya@example.com"}`))
	h.ServeHTTP(recRequest, reqRequest)
	if recRequest.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recRequest.Code, recRequest.Body.String())
	}

	var requestPayload map[string]any
	if err := json.NewDecoder(recRequest.Body).Decode(&requestPayload); err != nil {
		t.Fatalf("decode request payload: %v", err)
	}
	token, _ := requestPayload["token"].(string)
	if token == "" {
		t.Fatalf("expected token in response")
	}

	recVerify := httptest.NewRecorder()
	reqVerify := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/magic-link/verify", strings.NewReader(`{"email":"maya@example.com","token":"`+token+`","name":"Maya"}`))
	h.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recVerify.Code, recVerify.Body.String())
	}
	if len(recVerify.Result().Cookies()) == 0 {
		t.Fatalf("expected verify to issue session cookie")
	}
}

func TestEmailOTPPluginFlow(t *testing.T) {
	s := newPluginServer(t, plugins.EmailOTP(emailotp.Options{ExposeOTPInResponse: true}))
	h := s.Handler()

	recSend := httptest.NewRecorder()
	reqSend := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/email-otp/send", strings.NewReader(`{"email":"otp@example.com"}`))
	h.ServeHTTP(recSend, reqSend)
	if recSend.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recSend.Code, recSend.Body.String())
	}

	var sendPayload map[string]any
	if err := json.NewDecoder(recSend.Body).Decode(&sendPayload); err != nil {
		t.Fatalf("decode send payload: %v", err)
	}
	otp, _ := sendPayload["otp"].(string)
	if otp == "" {
		t.Fatalf("expected otp in response")
	}

	recVerify := httptest.NewRecorder()
	reqVerify := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/email-otp/verify", strings.NewReader(`{"email":"otp@example.com","otp":"`+otp+`","name":"OTP User"}`))
	h.ServeHTTP(recVerify, reqVerify)
	if recVerify.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recVerify.Code, recVerify.Body.String())
	}
}

func TestPasskeyRegistrationChallengeState(t *testing.T) {
	s := newPluginServer(t, plugins.Passkey(passkey.Options{}))
	h := s.Handler()

	recSignUp := httptest.NewRecorder()
	reqSignUp := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-up/email", strings.NewReader(`{"email":"p@example.com","password":"supersecure1","name":"Pass Key"}`))
	h.ServeHTTP(recSignUp, reqSignUp)
	if recSignUp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", recSignUp.Code, recSignUp.Body.String())
	}
	cookies := recSignUp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected cookie from signup")
	}

	recSession := httptest.NewRecorder()
	reqSession := httptest.NewRequest(http.MethodGet, "/auth/v1/get-session", nil)
	reqSession.AddCookie(cookies[0])
	h.ServeHTTP(recSession, reqSession)
	if recSession.Code != http.StatusOK {
		t.Fatalf("expected 200 get-session")
	}

	var sessionPayload map[string]any
	if err := json.NewDecoder(recSession.Body).Decode(&sessionPayload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	u, _ := sessionPayload["user"].(map[string]any)
	userID, _ := u["id"].(string)
	if userID == "" {
		t.Fatalf("expected user id")
	}

	recRegisterBegin := httptest.NewRecorder()
	reqRegisterBegin := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/passkey/register/begin", strings.NewReader(`{"userId":"`+userID+`"}`))
	reqRegisterBegin.AddCookie(cookies[0])
	h.ServeHTTP(recRegisterBegin, reqRegisterBegin)
	if recRegisterBegin.Code != http.StatusOK {
		t.Fatalf("expected 200 passkey register begin, got %d body=%s", recRegisterBegin.Code, recRegisterBegin.Body.String())
	}

	var beginPayload map[string]any
	if err := json.NewDecoder(recRegisterBegin.Body).Decode(&beginPayload); err != nil {
		t.Fatalf("decode register begin payload: %v", err)
	}
	options, _ := beginPayload["options"].(map[string]any)
	publicKey, _ := options["publicKey"].(map[string]any)
	challenge, _ := publicKey["challenge"].(string)
	if challenge == "" {
		t.Fatalf("expected webauthn challenge in options.publicKey.challenge")
	}

	recRegisterFinish := httptest.NewRecorder()
	reqRegisterFinish := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/passkey/register/finish", strings.NewReader(`{"userId":"`+userID+`","credential":{}}`))
	reqRegisterFinish.AddCookie(cookies[0])
	h.ServeHTTP(recRegisterFinish, reqRegisterFinish)
	if recRegisterFinish.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 passkey register finish for invalid attestation, got %d body=%s", recRegisterFinish.Code, recRegisterFinish.Body.String())
	}
}

func TestTwoFactorEmailSignInEnforcement(t *testing.T) {
	s := newPluginServer(t, plugins.TwoFactor(twofactor.Options{ExposeCodeInResponse: true}))
	h := s.Handler()

	recSignUp := httptest.NewRecorder()
	reqSignUp := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-up/email", strings.NewReader(`{"email":"2fa@example.com","password":"supersecure1","name":"Two Factor"}`))
	h.ServeHTTP(recSignUp, reqSignUp)
	if recSignUp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", recSignUp.Code, recSignUp.Body.String())
	}
	cookies := recSignUp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected cookie from signup")
	}

	recSession := httptest.NewRecorder()
	reqSession := httptest.NewRequest(http.MethodGet, "/auth/v1/get-session", nil)
	reqSession.AddCookie(cookies[0])
	h.ServeHTTP(recSession, reqSession)
	if recSession.Code != http.StatusOK {
		t.Fatalf("expected 200 get-session")
	}
	var sessionPayload map[string]any
	if err := json.NewDecoder(recSession.Body).Decode(&sessionPayload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	u, _ := sessionPayload["user"].(map[string]any)
	userID, _ := u["id"].(string)
	if userID == "" {
		t.Fatalf("expected user id")
	}

	recEnable2FA := httptest.NewRecorder()
	reqEnable2FA := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/2fa/enable", strings.NewReader(`{}`))
	reqEnable2FA.AddCookie(cookies[0])
	h.ServeHTTP(recEnable2FA, reqEnable2FA)
	if recEnable2FA.Code != http.StatusOK {
		t.Fatalf("expected 200 2fa enable, got %d body=%s", recEnable2FA.Code, recEnable2FA.Body.String())
	}

	var enablePayload map[string]any
	if err := json.NewDecoder(recEnable2FA.Body).Decode(&enablePayload); err != nil {
		t.Fatalf("decode 2fa enable payload: %v", err)
	}
	code, _ := enablePayload["code"].(string)
	if code == "" {
		t.Fatalf("expected setup code in response")
	}
	backupCodes, _ := enablePayload["backupCodes"].([]any)
	if len(backupCodes) == 0 {
		t.Fatalf("expected backup codes from 2FA enable")
	}
	firstBackupCode, _ := backupCodes[0].(string)
	if firstBackupCode == "" {
		t.Fatalf("expected first backup code")
	}

	recVerify2FA := httptest.NewRecorder()
	reqVerify2FA := httptest.NewRequest(http.MethodPost, "/auth/v1/plugins/2fa/verify", strings.NewReader(`{"userId":"`+userID+`","code":"`+code+`"}`))
	reqVerify2FA.AddCookie(cookies[0])
	h.ServeHTTP(recVerify2FA, reqVerify2FA)
	if recVerify2FA.Code != http.StatusOK {
		t.Fatalf("expected 200 2fa verify, got %d body=%s", recVerify2FA.Code, recVerify2FA.Body.String())
	}

	recSignInNoCode := httptest.NewRecorder()
	reqSignInNoCode := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-in/email", strings.NewReader(`{"email":"2fa@example.com","password":"supersecure1"}`))
	h.ServeHTTP(recSignInNoCode, reqSignInNoCode)
	if recSignInNoCode.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 sign-in without 2FA code, got %d body=%s", recSignInNoCode.Code, recSignInNoCode.Body.String())
	}
	if !strings.Contains(recSignInNoCode.Body.String(), "TWO_FACTOR_REQUIRED") {
		t.Fatalf("expected TWO_FACTOR_REQUIRED error, body=%s", recSignInNoCode.Body.String())
	}

	recSignInWithCode := httptest.NewRecorder()
	reqSignInWithCode := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-in/email", strings.NewReader(`{"email":"2fa@example.com","password":"supersecure1","twoFactorCode":"`+firstBackupCode+`"}`))
	h.ServeHTTP(recSignInWithCode, reqSignInWithCode)
	if recSignInWithCode.Code != http.StatusOK {
		t.Fatalf("expected 200 sign-in with backup code, got %d body=%s", recSignInWithCode.Code, recSignInWithCode.Body.String())
	}

	recReuseBackupCode := httptest.NewRecorder()
	reqReuseBackupCode := httptest.NewRequest(http.MethodPost, "/auth/v1/sign-in/email", strings.NewReader(`{"email":"2fa@example.com","password":"supersecure1","twoFactorCode":"`+firstBackupCode+`"}`))
	h.ServeHTTP(recReuseBackupCode, reqReuseBackupCode)
	if recReuseBackupCode.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 reusing consumed backup code, got %d body=%s", recReuseBackupCode.Code, recReuseBackupCode.Body.String())
	}
	if !strings.Contains(recReuseBackupCode.Body.String(), "INVALID_TWO_FACTOR_CODE") {
		t.Fatalf("expected INVALID_TWO_FACTOR_CODE when reusing backup code, body=%s", recReuseBackupCode.Body.String())
	}
}

func newPluginServer(t *testing.T, plugs ...plugin.Plugin) *Server {
	t.Helper()
	s, err := New(Config{
		Secret:       "01234567890123456789012345678901",
		PrimaryStore: memory.New(),
		EmailPassword: EmailPasswordConfig{
			Enabled: true,
		},
		RateLimit: RateLimitConfig{Enabled: false},
		Plugins:   plugs,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}
