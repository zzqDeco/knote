package knowledge

import (
	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/repository"
)

type Mode = versioned.Mode

const (
	ModeFake = versioned.ModeFake
	ModeReal = versioned.ModeReal
)

type Backend = versioned.Backend
type Service = versioned.Service
type Options = versioned.Options
type BuildResult = versioned.BuildResult
type Answer = versioned.Answer
type Explanation = versioned.Explanation

func New(opts Options) Service {
	return versioned.New(opts)
}

func RenderEvalReport(report repository.EvalReport) string {
	return versioned.RenderEvalReport(report)
}
