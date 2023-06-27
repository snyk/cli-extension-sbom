// package flag implements convenience-flag types to work with `github.com/spf13/pflag` and our
// configuration.
//
//nolint:ireturn // linter complains on an empty line about something...probably because generics.
package flag

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

// Flag is a generic Flag type.
type Flag[T string | bool] struct {
	// Name is the name of the flag.
	Name string
	// Shorthand of the flag, optional.
	Shorthand string
	// Usage text for this flag.
	Usage string
	// DefaultValue of this flag.
	DefaultValue T
}

// AddToFlagSet adds the flag to the given FlagSet, registering helptext, shorthands etc.
//
//nolint:forcetypeassert // type assertions are done implicitly through the switch.
func (f Flag[T]) AddToFlagSet(fs *pflag.FlagSet) {
	// The "any().(type)" statements are a workaround for https://github.com/golang/go/issues/49206,
	// which once implemented could be removed.
	switch any(f.DefaultValue).(type) {
	case string:
		if f.Shorthand != "" {
			fs.StringP(f.Name, f.Shorthand, any(f.DefaultValue).(string), f.Usage)
		} else {
			fs.String(f.Name, any(f.DefaultValue).(string), f.Usage)
		}
	case bool:
		if f.Shorthand != "" {
			fs.BoolP(f.Name, f.Shorthand, any(f.DefaultValue).(bool), f.Usage)
		} else {
			fs.Bool(f.Name, any(f.DefaultValue).(bool), f.Usage)
		}
	}
}

// AsArgument returns the flag including it's value as rendered on a command line. ok will be true
// if the flag is being set, and false otherwise. For boolean values, it treats the flag as a simple
// "switch" and will return ("", false) if the flag's value is "false" (instead of returning
// something like `-x=false`).
func (f Flag[T]) AsArgument(c configuration.Configuration) (arg string, ok bool) {
	val := f.Value(c)

	var zeroVal T
	if val == zeroVal {
		return "", false
	}

	switch s := any(val).(type) {
	case string:
		return "--" + f.Name + "=" + s, true
	case bool:
		return "--" + f.Name, true
	default:
		panic(fmt.Sprintf("unknown type for value: %T", s))
	}
}

// Value returns the value for this flag as stored in the configuration. If the flag is not set
// (e.g. is the zero-value for the respective type), the flag's DefaultValue will be returned.
func (f Flag[T]) Value(c configuration.Configuration) (val T) {
	v := c.Get(f.Name)
	if v == nil {
		return f.DefaultValue
	}

	var zeroVal T
	// this type cast should always succeed
	s, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("wrong type stored in config. expected %T, got %T", zeroVal, v))
	}

	if s == zeroVal {
		return f.DefaultValue
	}
	return s
}

// Flags is a list of Flags, and because we can't mix generic types (e.g. flag[string] and
// flag[bool]) in a single flag[T] slice, we need to use an interface instead.
//
//	f := Flags{
//	  Flag[bool]{...},
//	}
type Flags []interface {
	// AddToFlagSet adds a flag to the given flagset, registering the helptext and default values.
	AddToFlagSet(*pflag.FlagSet)
	// AsArgument returns the given flag plus a potential value extracted from the configuration.
	// For example, if there is a string flag "x", and the configuration has a value "y" set,
	// AsArgument would return "--x=y".
	// If the value is not set in the config, ok will be false to indicate the flag is not set.
	AsArgument(configuration.Configuration) (arg string, ok bool)
}

// AddToFlagSet adds all flags to the given flag set.
func (f Flags) AddToFlagSet(fs *pflag.FlagSet) {
	for _, flag := range f {
		flag.AddToFlagSet(fs)
	}
}
