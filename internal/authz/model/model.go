package model

import _ "embed"

// AuthorizationModel is the canonical OpenFGA DSL model deployed for knote decisions.
//
//go:embed authorization.fga
var AuthorizationModel string
