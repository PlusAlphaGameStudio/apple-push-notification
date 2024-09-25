package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"golang.org/x/net/http2"
)

type APNsPayload struct {
	Aps Aps `json:"aps"`
}

type Aps struct {
	Alert            string `json:"alert"`
	Badge            int    `json:"badge,omitempty"`
	Sound            string `json:"sound,omitempty"`
	ContentAvailable int    `json:"content-available,omitempty"`
	Category         string `json:"category,omitempty"`
	ThreadID         string `json:"thread-id,omitempty"`
}

func main() {
	goDotErr := godotenv.Load()
	if goDotErr != nil {
		log.Println("Error loading .env file")
	}

	// 필요한 정보 설정
	keyID := os.Getenv("PEM_KEY_ID")
	teamID := os.Getenv("TEAM_ID")
	bundleID := os.Getenv("BUNDLE_ID")
	deviceToken := os.Getenv("TEST_DEVICE_TOKEN")
	isProduction := os.Getenv("IS_PRODUCTION") == "1"

	// Auth Key 파일 로드
	privateKey, err := os.ReadFile(os.Getenv("PEM_FILE_PATH"))
	if err != nil {
		panic(err)
	}

	// JWT 토큰 생성
	jwtToken, err := generateJWTToken(keyID, teamID, privateKey)
	if err != nil {
		panic(err)
	}

	// 푸시 알림 페이로드 구성
	payload := APNsPayload{
		Aps: Aps{
			Alert: "안녕하세요! 푸시 알림 테스트입니다.",
			//Sound: "default",
			//Badge: 1,
		},
	}

	// 푸시 알림 전송
	err = sendPushNotification(deviceToken, payload, jwtToken, bundleID, isProduction)
	if err != nil {
		fmt.Printf("푸시 알림 전송 오류: %v\n", err)
	}
}

func generateJWTToken(keyID, teamID string, privateKey []byte) (string, error) {
	now := time.Now()
	claims := jwt.StandardClaims{
		Issuer:   teamID,
		IssuedAt: now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	// 개인 키 파싱
	var key any
	var err error

	for block, rest := pem.Decode(privateKey); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}

			// Handle certificate
			fmt.Printf("%T %#v\n", cert, cert)

		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				panic(err)
			}

			// Handle private key
			fmt.Printf("%T %#v\n", key, key)

		default:
			panic("unknown block type")
		}
	}

	// 토큰 서명
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func sendPushNotification(deviceToken string, payload APNsPayload, jwtToken, bundleID string, isProduction bool) error {
	// APNs 엔드포인트 설정
	var apnsURL string
	if isProduction {
		apnsURL = "https://api.push.apple.com/3/device/"
	} else {
		apnsURL = "https://api.sandbox.push.apple.com/3/device/"
	}
	url := apnsURL + deviceToken

	// 페이로드 직렬화
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// HTTP 요청 생성
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}

	// 헤더 설정
	req.Header.Set("apns-topic", bundleID)
	req.Header.Set("authorization", fmt.Sprintf("bearer %s", jwtToken))
	req.Header.Set("Content-Type", "application/json")

	// HTTP/2 클라이언트 설정
	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	// 요청 보내기
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// 응답 처리
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		fmt.Println("푸시 알림 전송 성공")
		return nil
	} else {
		fmt.Printf("푸시 알림 전송 실패: %s\n", body)
		return fmt.Errorf("APNs error: %s", body)
	}
}
