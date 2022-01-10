package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var secrets map[string]interface{}

var oidc struct {
	iss	string
	clientId         string
	clientSecret     string
	state            string
	authEndpoint     string
	tokenEndpoint    string
	userInfoEndpoint string
	keyEndpoint      string
	nonce            string
}

const (
	response_type = "code"
	redirect_uri  = "http://localhost:8080/callback"
	grant_type    = "authorization_code"

	scope = "openid profile"
	LOCAL = true
)

func readJson() {
	data, err := ioutil.ReadFile("client_secret.json")
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(data, &secrets)
	return
}

func setUp() {

	readJson()
	if LOCAL {
		oidc.iss = "https://oreore.oidc.com"
		oidc.clientId = "1234"
		oidc.clientSecret = "secret"
		oidc.authEndpoint = "http://localhost:8081/auth"
		oidc.tokenEndpoint = "http://localhost:8081/token"
		oidc.userInfoEndpoint = "http://localhost:8081/userinfo"
		oidc.keyEndpoint = "http://localhost:8081/certs"
	} else {
		oidc.iss = "https://accounts.google.com"
		oidc.clientId = secrets["web"].(map[string]interface{})["client_id"].(string)
		oidc.clientSecret = secrets["web"].(map[string]interface{})["client_secret"].(string)
		oidc.authEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
		oidc.tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"
		oidc.userInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo"
		oidc.keyEndpoint = "https://www.googleapis.com/oauth2/v3/certs"
	}
	oidc.state = "xyz"
	oidc.nonce = "abc"

}

func login(w http.ResponseWriter, req *http.Request) {

	v := url.Values{}
	v.Add("response_type", response_type)
	v.Add("client_id", oidc.clientId)
	v.Add("state", oidc.state)
	v.Add("scope", scope)
	v.Add("redirect_uri", redirect_uri)
	v.Add("nonce", oidc.nonce)

	log.Printf("http redirect to: %s", fmt.Sprintf("%s?%s", oidc.authEndpoint, v.Encode()))
	// Googleの認可エンドポイントにリダイレクトさせる
	http.Redirect(w, req, fmt.Sprintf("%s?%s", oidc.authEndpoint, v.Encode()), 302)
}

func tokenRequest(query url.Values, c *http.Cookie) (map[string]interface{}, error) {

	v := url.Values{}
	v.Add("client_id", oidc.clientId)
	v.Add("client_secret", oidc.clientSecret)
	v.Add("grant_type", grant_type)
	v.Add("code", query.Get("code"))
	v.Add("redirect_uri", redirect_uri)

	req, err := http.NewRequest("POST", oidc.tokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.AddCookie(c)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var token map[string]interface{}
	json.Unmarshal(body, &token)

	log.Printf("token response :%s\n", string(body))

	return token, nil
}

func callback(w http.ResponseWriter, req *http.Request) {

	query := req.URL.Query()
	c, _ := req.Cookie("session")
	token, err := tokenRequest(query, c)
	if err != nil {
		log.Println(err)
	}

	id_token := token["id_token"].(string)
	verifyJWT(id_token)
	jwtdata := decodeJWT(id_token)
	err = verifyJWTSignature(jwtdata, id_token)
	if err != nil {
		log.Printf("verify JWT Signature err : %s", err)
	}

	err = verifyToken(jwtdata, token["access_token"].(string))
	if err != nil {
		log.Printf("verifyToken is err : %s", err)
	}

	userInfoURL := oidc.userInfoEndpoint
	log.Println(userInfoURL)
	req, err = http.NewRequest("GET", userInfoURL, nil)
	if nil != err {
		log.Println(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token["access_token"].(string)))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}
	//log.Println(string(body))

	w.Write([]byte(body))

}

func main() {
	setUp()
	http.HandleFunc("/login", login)
	http.HandleFunc("/callback", callback)
	if LOCAL {
		log.Println("start server localhost:8080...")
		log.Println("oidc server is local mode")
	}
	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
