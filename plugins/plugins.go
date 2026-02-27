package plugins

import (
	"github.com/captjt/go-auth/plugin"
	"github.com/captjt/go-auth/plugins/emailotp"
	"github.com/captjt/go-auth/plugins/magiclink"
	"github.com/captjt/go-auth/plugins/passkey"
	"github.com/captjt/go-auth/plugins/twofactor"
	"github.com/captjt/go-auth/plugins/username"
)

func Username(opts username.Options) plugin.Plugin {
	return username.New(opts)
}

func MagicLink(opts magiclink.Options) plugin.Plugin {
	return magiclink.New(opts)
}

func EmailOTP(opts emailotp.Options) plugin.Plugin {
	return emailotp.New(opts)
}

func Passkey(opts passkey.Options) plugin.Plugin {
	return passkey.New(opts)
}

func TwoFactor(opts twofactor.Options) plugin.Plugin {
	return twofactor.New(opts)
}
