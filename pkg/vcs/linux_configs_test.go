// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/stretchr/testify/assert"
)

func TestDropLinuxSanitizerConfigs(t *testing.T) {
	tests := []struct {
		name  string
		types []crash.Type
		test  func(*testing.T, *kconfig.ConfigFile)
	}{
		{
			name:  "warning",
			types: []crash.Type{crash.Warning},
			test: func(t *testing.T, cf *kconfig.ConfigFile) {
				assertConfigs(t, cf, "BUG")
				assert.Equal(t,
					`"param1=a param2=b rcupdate.rcu_cpu_stall_suppress=1"`,
					cf.Value("CMDLINE"),
				)
			},
		},
		{
			name:  "kasan bug",
			types: []crash.Type{crash.KASAN},
			test: func(t *testing.T, cf *kconfig.ConfigFile) {
				assertConfigs(t, cf, "KASAN")
			},
		},
		{
			name:  "warning & kasan bug",
			types: []crash.Type{crash.Warning, crash.KASAN},
			test: func(t *testing.T, cf *kconfig.ConfigFile) {
				assertConfigs(t, cf, "KASAN", "BUG")
			},
		},
		{
			name:  "lockdep",
			types: []crash.Type{crash.LockdepBug},
			test: func(t *testing.T, cf *kconfig.ConfigFile) {
				assertConfigs(t, cf, "LOCKDEP")
			},
		},
		{
			name:  "rcu stall",
			types: []crash.Type{crash.Hang},
			test: func(t *testing.T, cf *kconfig.ConfigFile) {
				assertConfigs(t, cf, "RCU_STALL_COMMON")
				assert.Equal(t, `"param1=a param2=b"`, cf.Value("CMDLINE"))
			},
		},
	}

	const base = `
CONFIG_CMDLINE="param1=a param2=b"
CONFIG_BUG=y
CONFIG_KASAN=y
CONFIG_LOCKDEP=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_UBSAN=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
`
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			conf, err := kconfig.ParseConfigData([]byte(base), "base")
			if err != nil {
				t.Fatal(err)
			}
			setLinuxSanitizerConfigs(conf, test.types, &debugtracer.NullTracer{})
			test.test(t, conf)
		})
	}
}

func assertConfigs(t *testing.T, cf *kconfig.ConfigFile, names ...string) {
	var setConfigs []string
	for _, name := range names {
		if cf.Value(name) == kconfig.Yes {
			setConfigs = append(setConfigs, name)
		}
	}
	assert.ElementsMatch(t, setConfigs, names)
}