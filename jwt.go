package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"github.com/golang-jwt/jwt"
	"log"
	"net/http"
	"time"

	//"crypto"
	"crypto/rsa"
	//"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

type JwtData struct {
	header_payload string
	header         map[string]interface{}
	header_raw     string
	payLoad        map[string]interface{}
	payLoad_raw    string
	signature      string
}

func base64URLEncode(str string) string {
	hash := sha256.Sum256([]byte(str))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func fillB64Length(jwt string) (b64 string) {
	replace := strings.NewReplacer("-", "+", "_", "/")
	b64 = replace.Replace(jwt)

	if len(jwt)%4 != 0 {
		addLength := len(jwt) % 4
		for i := 0; i < addLength; i++ {
			b64 += "="
		}
	}

	return b64
}

func decodeJWT(idToken string) (jwtdata JwtData) {
	tmp := strings.Split(idToken, ".")
	jwtdata.header_payload = fmt.Sprintf("%s.%s", tmp[0], tmp[1])
	jwtdata.header_raw = tmp[0]
	jwtdata.payLoad_raw = tmp[1]

	header := fillB64Length(tmp[0])
	payload := fillB64Length(tmp[1])

	decHeader, _ := base64.StdEncoding.DecodeString(header)
	decPayload, _ := base64.StdEncoding.DecodeString(payload)
	decSignature, _ := base64.RawURLEncoding.DecodeString(tmp[2])
	jwtdata.signature = string(decSignature)

	json.NewDecoder(bytes.NewReader(decHeader)).Decode(&jwtdata.header)
	json.NewDecoder(bytes.NewReader(decPayload)).Decode(&jwtdata.payLoad)

	return jwtdata
}

func verifyJWTSignature(jwtdata JwtData, id_token string) error {

	pubkey := rsa.PublicKey{}
	var keyList map[string]interface{}

	keyURL := "https://www.googleapis.com/oauth2/v3/certs"
	req, err := http.NewRequest("GET", keyURL, nil)
	if err != nil {
		return fmt.Errorf("http request err : %s\n", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http client err : %s\n", err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&keyList)

	for _, val := range keyList["keys"].([]interface{}) {
		key := val.(map[string]interface{})
		if key["kid"] == jwtdata.header["kid"].(string) {
			number, _ := base64.RawURLEncoding.DecodeString(key["n"].(string))
			pubkey.N = new(big.Int).SetBytes(number)
			pubkey.E = 65537
		}
	}

	hasher := sha256.New()
	hasher.Write([]byte(jwtdata.header_payload))

	// 標準pkgの機能で署名検証
	err = rsa.VerifyPKCS1v15(&pubkey, crypto.SHA256, hasher.Sum(nil), []byte(jwtdata.signature))
	if err != nil {
		return fmt.Errorf("Verify err : %s\n", err)
	} else {
		log.Println("Verify success by VerifyPKCS1v15!!")
	}

	derRsaPubKey, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derRsaPubKey})
	if err != nil {
		return err
	}

	// golang-jwtライブラリで署名検証
	// https://github.com/golang-jwt/jwt/blob/main/cmd/jwt/main.go
	token, err := jwt.Parse(id_token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM(buf.Bytes())
	})
	if err != nil {
		log.Printf("couldn't parse token: %s \n", err)
	}
	if !token.Valid {
		log.Println("token is invalid")
	} else {
		log.Println("token is valid!!")
	}
	return nil
}

func verifyToken(data JwtData, access_token string) error {

	// トークン発行元の確認
	if "https://accounts.google.com" != data.payLoad["iss"].(string) {
		return fmt.Errorf("iss not match")
	}
	// クライアントIDの確認
	if oidc.clientId != data.payLoad["aud"].(string) {
		return fmt.Errorf("acoount_id not match")
	}
	// nonceの確認
	if oidc.nonce != data.payLoad["nonce"].(string) {
		return fmt.Errorf("nonce is not match")
	}
	// IDトークンの有効期限を期限を確認
	now := time.Now().Unix()
	if data.payLoad["exp"].(float64) < float64(now) {
		return fmt.Errorf("token time limit expired")
	}
	// at_hashのチェック
	token_athash := base64URLEncode(access_token)
	if token_athash[0:21] != data.payLoad["at_hash"].(string)[0:21] {
		return fmt.Errorf("at_hash not match")
	}

	return nil
}
