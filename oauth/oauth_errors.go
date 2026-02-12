package oauth

import "errors"

var ErrOAuthStateMissing = errors.New("oauth state missing")
var ErrOAuthStateInvalid = errors.New("oauth state invalid")
var ErrOAuthStateMismatch = errors.New("oauth state mismatch")
var ErrOAuthCallbackInvalid = errors.New("oauth callback invalid")
var ErrOAuthProvider = errors.New("oauth provider error")
var ErrOAuthProviderNotFound = errors.New("oauth provider not found")
var ErrOAuthCodeMissing = errors.New("oauth code missing")
var ErrOAuthAccountMissingUserID = errors.New("oauth account missing user id")
var ErrOAuthEmailMissing = errors.New("oauth email missing")
var ErrOAuthEmailAlreadyRegistered = errors.New("oauth email already registered")
var ErrOAuthTokenExchange = errors.New("oauth token exchange failed")
var ErrOAuthUserInfo = errors.New("oauth userinfo fetch failed")
var ErrOAuthIDTokenMissing = errors.New("oauth id_token missing")
var ErrOAuthIDTokenInvalid = errors.New("oauth id_token invalid")
