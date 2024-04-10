package view

import (
	"bytes"
	"html/template"
)

type untestedComponents struct {
	components []component

	str string
}

type Component struct {
	Reference string
	Info      string
}

type component struct {
	Reference string
	Info      string
}

// generateUntestedComponents constructs a list of untested components and generates it's
// string representation intended for human readable output.
//
// Function returns an error if generation of string representation fails.
func generateUntestedComponents(components ...Component) (*untestedComponents, error) {
	if len(components) == 0 {
		return &untestedComponents{}, nil
	}

	comps := make([]component, len(components))
	for i := range components {
		comps[i] = component{
			Reference: sectionStyle.Render(components[i].Reference),
			Info:      components[i].Info,
		}
	}

	s := untestedComponents{
		components: comps,
	}

	if err := s.computeString(); err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *untestedComponents) computeString() error {
	var buff bytes.Buffer

	err := untestedComponentsTemplate.Execute(&buff, struct {
		Title      string
		Components []component
	}{
		Title:      sectionStyle.Render("Untested packages:"),
		Components: s.components,
	})

	if err != nil {
		return err
	}

	s.str = buff.String()
	s.str = untestedStyle.Render(s.str[:len(s.str)-1])

	return nil
}

func (s *untestedComponents) String() string {
	return s.str
}

var untestedComponentsTemplate *template.Template = template.Must(template.New("untestedComponents").
	Parse(`{{.Title}}
{{range .Components}}
× {{.Reference}}
  Info: {{.Info}}
{{end}}`))
