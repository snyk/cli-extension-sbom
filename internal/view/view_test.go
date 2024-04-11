package view

import (
	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)
}
