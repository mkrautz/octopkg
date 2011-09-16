package octopkg

import (
	"encoding/hex"
	"gorilla.googlecode.com/hg/gorilla/sessions"
	"json"
	"os"
)

type config struct {
	SessionHMACSecret string
	SessionAESSecret  string
}

var Config config

func init() {
	err := ReadConfig("octopkg.conf", &Config)
	if err != nil {
		panic(err.String())
	}

	sessions.DefaultSessionFactory.SetStoreKeys("cookie", Config.SessionHMACSecretBytes(), Config.SessionAESSecretBytes())
}

func ReadConfig(fn string, cfg *config) os.Error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(f)
	err = decoder.Decode(&Config)
	if err != nil {
		return err
	}

	return nil
}

func (cfg *config) SessionHMACSecretBytes() []byte {
	buf, err := hex.DecodeString(cfg.SessionHMACSecret)
	if err != nil {
		panic(err.String())
	}
	return buf
}

func (cfg *config) SessionAESSecretBytes() []byte {
	buf, err := hex.DecodeString(cfg.SessionAESSecret)
	if err != nil {
		panic(err.String())
	}
	return buf
}
