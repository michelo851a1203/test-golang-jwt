package useJwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestCreateTokenCore(t *testing.T) {
	assert := assert.New(t)

	userName := "Testing Account"
	current := time.Now()

	expiredTime := current.Add(20 * time.Minute)
	testId := fmt.Sprintf("user+%d", current.UnixNano())

	useJwtModel := UseJwtModel{}
	myClaims := MyClaims{
		Account: userName,
		Role:    "member",
		StandardClaims: jwt.StandardClaims{
			Audience:  userName,
			ExpiresAt: expiredTime.Unix(),
			Id:        testId,
			IssuedAt:  current.Unix(),
			Issuer:    "GinJwt",
			NotBefore: current.Unix(),
			Subject:   userName,
		},
	}

	token, err := useJwtModel.CreateTokenCore(&myClaims)
	assert.Nil(err)
	splitTokenArray := strings.Split(token, ".")
	assert.Equal(3, len(splitTokenArray))
	tokenStringBody := splitTokenArray[1]
	decodeBase64Container, err := base64.StdEncoding.DecodeString(tokenStringBody)
	assert.Nil(err)
	jsonContainer, err := json.Marshal(myClaims)
	assert.Nil(err)
	assert.Equal(string(decodeBase64Container), string(jsonContainer))
}

func TestValidateToken(t *testing.T) {
	assert := assert.New(t)

	userName := "Testing Account"
	current := time.Now()

	expiredTime := current.Add(20 * time.Minute)
	testId := fmt.Sprintf("user+%d", current.UnixNano())

	useJwtModel := UseJwtModel{}
	myClaims := MyClaims{
		Account: userName,
		Role:    "member",
		StandardClaims: jwt.StandardClaims{
			Audience:  userName,
			ExpiresAt: expiredTime.Unix(),
			Id:        testId,
			IssuedAt:  current.Unix(),
			Issuer:    "GinJwt",
			NotBefore: current.Unix(),
			Subject:   userName,
		},
	}

	token, err := useJwtModel.CreateTokenCore(&myClaims)
	assert.Nil(err)
	validatedClaims, err := useJwtModel.ValidateToken(token)
	assert.Nil(err)
	resultContainer, err := json.Marshal(validatedClaims)
	assert.Nil(err)
	expectedContainer, err := json.Marshal(myClaims)
	assert.Nil(err)
	fmt.Println(string(expectedContainer), string(resultContainer))
}
