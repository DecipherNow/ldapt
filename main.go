// Copyright 2019 Decipher Technology Studios
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"

	"github.com/deciphernow/ldapt/ldap"
	"github.com/gobuffalo/packr"
	"github.com/rs/zerolog/log"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate go run generate.go .

// Password represents the body of a post to the /passwords route.
type Password struct {
	User string `json:"user" binding:"required"`
	Old  string `json:"old" binding:"required"`
	New  string `json:"new" binding:"required"`
}

// Version and commit are populated at compile time.
var version string
var commit string

func main() {

	if err := configure(); err != nil {
		log.Fatal().AnErr("stack", err).Msg("error raised during configuration")
	}

	connector := ldap.NewConnector(viper.GetString("connector.host"), viper.GetInt("connector.port"), viper.GetBool("connector.secure"))
	resolver := ldap.NewResolver(connector, viper.GetString("resolver.base"), viper.GetString("resolver.template"), viper.GetString("resolver.distinguishedName"), viper.GetString("resolver.password"))
	router := gin.Default()
	static := packr.NewBox("./static")

	router.GET("/", func(context *gin.Context) {
		html, err := static.FindString("index.html")
		if err != nil {
			context.Data(http.StatusInternalServerError, "text/html", []byte("internal server error"))
		} else {
			context.Data(http.StatusOK, "text/html", []byte(html))
		}
	})

	router.GET("/api/version", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"version": version, "commit": commit})
	})

	router.POST("/api/passwords", func(context *gin.Context) {

		var password Password
		if err := context.BindJSON(&password); err != nil {
			log.Error().AnErr("", err).Msg("error raised parsing message body")
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		distinguishedNames, err := resolver.Resolve(password.User)
		if err != nil {
			log.Error().AnErr("", err).Msgf("error raised resolving distinguished names for %s", password.User)
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		switch len(distinguishedNames) {
		case 0:
			log.Info().Msgf("no entries found for %s", password.User)
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid user or password"})
			return
		case 1:
			err := ldap.ChangePassword(connector, distinguishedNames[0], password.Old, password.New)
			if err != nil {
				log.Info().Msgf("unable to change password for %s", distinguishedNames[0])
				context.JSON(http.StatusBadRequest, gin.H{"error": "invalid user or password"})
				return
			}
		default:
			log.Error().AnErr("", err).Msgf("multiple entries found for user %s", password.User)
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		context.String(http.StatusCreated, "")
	})

	router.Run()
}

func configure() error {
	var err error
	var path string
	pflag.StringVarP(&path, "config", "c", "config.json", "path to configuration file")
	pflag.Parse()
	viper.SetConfigFile(path)
	if err = viper.ReadInConfig(); err != nil {
		return errors.Wrapf(err, "error raised while reading config %s", path)
	}
	return nil
}
