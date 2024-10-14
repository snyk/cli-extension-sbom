package view

import (
	"bytes"
	"slices"
	"text/template"
)

type warnings struct {
	str string
	ws  []Warning
}

func generateWarnings(ws ...Warning) (*warnings, error) {
	if len(ws) == 0 {
		return &warnings{}, nil
	}

	w := warnings{ws: ws}

	slices.Reverse(w.ws)

	if err := w.computeString(); err != nil {
		return nil, err
	}

	return &w, nil
}

func (w *warnings) computeString() error {
	var buff bytes.Buffer

	err := warningsTemplate.Execute(&buff, struct {
		Title    string
		Warnings []Warning
	}{
		Title:    sectionStyle.Render("⚠️  Warnings:"),
		Warnings: w.ws,
	})

	if err != nil {
		return err
	}

	w.str = buff.String()

	return nil
}

func (w *warnings) String() string {
	return w.str
}

var warningsTemplate *template.Template = template.Must(template.New("warnings").
	Parse(`{{.Title}}
{{range .Warnings}}
· {{.}}{{end}}`))
