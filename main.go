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
	amqp "github.com/rabbitmq/amqp091-go"
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

type Notification struct {
	Title    string `json:"title,omitempty"`
	Body     string `json:"body,omitempty"`
	ImageURL string `json:"image,omitempty"`
}

type Message struct {
	Data         map[string]string `json:"data,omitempty"`
	Token        string            `json:"token,omitempty"`
	Notification *Notification     `json:"notification,omitempty"`
}

func main() {
	goDotErr := godotenv.Load()
	if goDotErr != nil {
		log.Println("Error loading .env file")
	}

	deliveries, err := initMq()
	if err != nil {
		panic(err)
	}

	client := initHttpClient()

	// 필요한 정보 설정
	keyID := os.Getenv("PEM_KEY_ID")
	teamID := os.Getenv("TEAM_ID")
	bundleID := os.Getenv("BUNDLE_ID")
	//deviceToken := os.Getenv("TEST_DEVICE_TOKEN")
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

	// 요청 메시지 받기 시작
	for {
		select {
		case delivery := <-deliveries:
			log.Printf("%v\n", string(delivery.Body))
			var message Message
			err := json.Unmarshal(delivery.Body, &message)
			if err != nil {
				_ = delivery.Reject(false)
				continue
			}

			// 푸시 알림 페이로드 구성
			payload := APNsPayload{
				Aps: Aps{
					Alert: message.Notification.Body,
					//Sound: "default",
					//Badge: 1,
				},
			}

			// 푸시 알림 전송
			err = sendPushNotification(client, message.Token, payload, jwtToken, bundleID, isProduction)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("Success")
			}

			_ = delivery.Ack(false)
		}
	}
}

func initHttpClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}
}

func initMq() (<-chan amqp.Delivery, error) {
	conn, err := amqp.Dial(os.Getenv("FCMCG_RMQ_ADDR"))
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}

	err = ch.Confirm(false)
	if err != nil {
		return nil, err
	}

	queueName := "apple-push-notification"

	_, err = ch.QueueDeclare(
		queueName,
		false,
		false,
		false,
		false,
		nil)
	if err != nil {
		return nil, err
	}

	deliveries, err := ch.Consume(
		queueName,
		"",
		false,
		false,
		false,
		false,
		nil,
	)

	if err != nil {
		return nil, err
	}

	return deliveries, nil
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

func sendPushNotification(client *http.Client, deviceToken string, payload APNsPayload, jwtToken, bundleID string, isProduction bool) error {
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
		return nil
	} else {
		return fmt.Errorf("APNs error: %s", body)
	}
}
