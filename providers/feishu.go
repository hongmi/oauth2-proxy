package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GitHubProvider represents an GitHub based Identity Provider
//--provider=feishu
//--upstream=file:///Users/hongmin/websites/httrack.com/#/
//--email-domain=smallsmallbird.xyz
//--http-address=0.0.0.0:4180
//--cookie-secure=false
//--metrics-address=0.0.0.0:4181
//--cookie-refresh=90m
type FeishuProvider struct {
	*ProviderData
	Org   string
	Team  string
	Repo  string
	Token string
	Users []string
}

var _ Provider = (*FeishuProvider)(nil)

const (
	feishuProviderName = "FeiShu"
	feishuDefaultScope = "user:email"
)

var (
	// Default Login URL for FeiShu.
	// Pre-parsed URL of https://open.feishu.cn/open-apis/authen/v1/index?redirect_uri={REDIRECT_URI}&app_id={APPID}&state={STATE}
	feishuDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "open.feishu.cn",
		Path:   "/open-apis/authen/v1/index",
	}

	// Default Redeem URL for FeiShu.
	// Pre-parsed URL of https://open.feishu.cn/open-apis/authen/v1/access_token
	feishuDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "open.feishu.cn",
		Path:   "/open-apis/authen/v1/access_token",
	}

	// Default Validation URL for GitHub.
	// ValidationURL is the API Base URL.
	// Other API requests are based off of this (eg to fetch users/groups).
	// Pre-parsed URL of https://api.github.com/.
	feishuDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "open.feishu.cn",
		Path:   "/open-apis/authen/v1/user_info",
	}

	feishuGetAppAccessTokenURL = &url.URL{
		Scheme: "https",
		Host:   "open.feishu.cn",
		Path:   "/open-apis/auth/v3/tenant_access_token/internal/",
	}

	feishuRefreshUserAccessTokenURL = &url.URL{
		Scheme: "https",
		Host:   "open.feishu.cn",
		Path:   "/open-apis/authen/v1/refresh_access_token",
	}
)

// NewGitHubProvider initiates a new FeishuProvider
func NewFeishuProvider(p *ProviderData) *FeishuProvider {
	p.setProviderDefaults(providerDefaults{
		name:        feishuProviderName,
		loginURL:    feishuDefaultLoginURL,
		redeemURL:   feishuDefaultRedeemURL,
		profileURL:  feishuDefaultValidateURL,
		validateURL: feishuDefaultValidateURL,
		scope:       feishuDefaultScope,
	})
	return &FeishuProvider{ProviderData: p}
}

// GetLoginURL makes the LoginURL with optional nonce support
func (p *FeishuProvider) GetLoginURL(redirectURI, state, nonce string) string {
	extraParams := url.Values{}

	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("app_id", p.ClientID)
	params.Add("state", state)
	for n, p := range extraParams {
		for _, v := range p {
			params.Add(n, v)
		}
	}
	a.RawQuery = params.Encode()

	return a.String()
}

func (p *FeishuProvider) getAppAccessToken(ctx context.Context) (string, error) {
	req := &struct {
		AppID     string `json:"app_id"`
		AppSecret string `json:"app_secret"`
	}{
		AppID:     p.ProviderData.ClientID,
		AppSecret: p.ProviderData.ClientSecret,
	}
	reqBytes, _ := json.Marshal(req)

	var jsonResponse struct {
		Code              int    `json:"code"`
		Msg               string `json:"msg"`
		TenantAccessToken string `json:"tenant_access_token"`
		Expire            int    `json:"expire"`
	}

	if err := requests.New(feishuGetAppAccessTokenURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(string(reqBytes))).
		SetHeader("Content-Type", "application/json; charset=utf-8").
		Do().
		UnmarshalInto(&jsonResponse); err != nil {
		return "", err
	}

	if jsonResponse.Code != 0 {
		errorStr := fmt.Sprintf("get app access_token failed, code:%v, msg:%s", jsonResponse.Code, jsonResponse.Msg)
		return "", errors.New(errorStr)
	}
	return jsonResponse.TenantAccessToken, nil
}

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *FeishuProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	appAccessToken, err := p.getAppAccessToken(ctx)
	if err != nil {
		fmt.Printf("fail to get app access_token %v\n", err)
		return nil, err
	}

	req := &struct {
		Code      string `json:"code"`
		GrantType string `json:"grant_type"`
	}{
		Code:      code,
		GrantType: "authorization_code",
	}
	reqBytes, _ := json.Marshal(req)

	var jsonResponse struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			AccessToken      string `json:"access_token"`
			AvatarURL        string `json:"avatar_url"`
			AvatarThumb      string `json:"avatar_thumb"`
			AvatarMiddle     string `json:"avatar_middle"`
			AvatarBig        string `json:"avatar_big"`
			ExpiresIn        int    `json:"expires_in"`
			Name             string `json:"name"`
			EnName           string `json:"en_name"`
			OpenID           string `json:"open_id"`
			UnionID          string `json:"union_id"`
			Email            string `json:"email"`
			UserID           string `json:"user_id"`
			Mobile           string `json:"mobile"`
			TenantKey        string `json:"tenant_key"`
			RefreshExpiresIn int    `json:"refresh_expires_in"`
			RefreshToken     string `json:"refresh_token"`
			TokenType        string `json:"token_type"`
		} `json:"data"`
	}

	if err := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(string(reqBytes))).
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetHeader("Authorization", "Bearer "+appAccessToken).
		Do().
		UnmarshalInto(&jsonResponse); err != nil {
		return nil, err
	}

	if jsonResponse.Code != 0 {
		errorStr := fmt.Sprintf("get access_token failed, code:%v, msg:%s", jsonResponse.Code, jsonResponse.Msg)
		return nil, errors.New(errorStr)
	}

	created := time.Now()
	expires := created.Add(time.Duration(jsonResponse.Data.ExpiresIn) * time.Second).Truncate(time.Second)

	data := jsonResponse.Data
	return &sessions.SessionState{
		CreatedAt:    &created,
		ExpiresOn:    &expires,
		AccessToken:  data.AccessToken,
		IDToken:      "",
		RefreshToken: data.RefreshToken,
		Nonce:        nil,
		Email:        data.Email,
		User:         data.Name,
		Groups:       nil,
	}, nil
}

func (p *FeishuProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.Email == "" {
		return "example@abc.com", nil
	}
	return s.Email, nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *FeishuProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed user access token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *FeishuProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {

	appAccessToken, err := p.getAppAccessToken(ctx)
	if err != nil {
		fmt.Printf("fail to get app access_token %v\n", err)
		return err
	}

	req := &struct {
		RefreshToken string `json:"refresh_token"`
		GrantType    string `json:"grant_type"`
	}{
		RefreshToken: s.RefreshToken,
		GrantType:    "refresh_token",
	}
	reqBytes, _ := json.Marshal(req)

	var jsonResponse struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			AccessToken      string `json:"access_token"`
			AvatarURL        string `json:"avatar_url"`
			AvatarThumb      string `json:"avatar_thumb"`
			AvatarMiddle     string `json:"avatar_middle"`
			AvatarBig        string `json:"avatar_big"`
			ExpiresIn        int    `json:"expires_in"`
			Name             string `json:"name"`
			EnName           string `json:"en_name"`
			OpenID           string `json:"open_id"`
			UnionID          string `json:"union_id"`
			Email            string `json:"email"`
			UserID           string `json:"user_id"`
			Mobile           string `json:"mobile"`
			TenantKey        string `json:"tenant_key"`
			RefreshExpiresIn int    `json:"refresh_expires_in"`
			RefreshToken     string `json:"refresh_token"`
			TokenType        string `json:"token_type"`
		} `json:"data"`
	}

	if err := requests.New(feishuRefreshUserAccessTokenURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(string(reqBytes))).
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetHeader("Authorization", "Bearer "+appAccessToken).
		Do().
		UnmarshalInto(&jsonResponse); err != nil {
		return err
	}

	if jsonResponse.Code != 0 {
		errorStr := fmt.Sprintf("refresh access_token failed, code:%v, msg:%s", jsonResponse.Code, jsonResponse.Msg)
		return errors.New(errorStr)
	}

	data := jsonResponse.Data

	now := time.Now()
	expires := now.Add(time.Duration(data.ExpiresIn) * time.Second).Truncate(time.Second)
	s.AccessToken = data.AccessToken
	s.RefreshToken = data.RefreshToken
	s.CreatedAt = &now
	s.ExpiresOn = &expires
	if data.Email != "" {
		s.Email = data.Email
	}

	return nil
}

// ValidateSessionState validates the AccessToken
func (p *FeishuProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	var jsonResponse struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			AvatarURL    string `json:"avatar_url"`
			AvatarThumb  string `json:"avatar_thumb"`
			AvatarMiddle string `json:"avatar_middle"`
			AvatarBig    string `json:"avatar_big"`
			Name         string `json:"name"`
			EnName       string `json:"en_name"`
			OpenID       string `json:"open_id"`
			UnionID      string `json:"union_id"`
			Email        string `json:"email"`
			UserID       string `json:"user_id"`
			Mobile       string `json:"mobile"`
			TenantKey    string `json:"tenant_key"`
		} `json:"data"`
	}

	if err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Content-Type", "application/json; charset=utf-8").
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&jsonResponse); err != nil {
		fmt.Printf("fail to get userinfo for validate session %v\n", err)
		return false
	}

	if jsonResponse.Code != 0 {
		fmt.Printf("fail to get userinfo for validate session, code:%v, msg:%s\n",
			jsonResponse.Code, jsonResponse.Msg)
		return false
	}

	return true
}
