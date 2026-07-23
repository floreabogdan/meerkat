package rules

import (
	"os"
	"time"

	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/suricata"
)

// Status is everything the console needs to describe the state of rule
// management in one glance — including, importantly, the reasons it might not
// work here. A page that offers an Apply button which silently does nothing is
// worse than a page that explains it cannot.
type Status struct {
	store.RuleCounts

	// RulesFile is the built ruleset meerkat reads. Readable says whether it
	// actually can: it is root-owned and world-readable on Debian, but that is
	// a default somebody may have tightened.
	RulesFile string
	Readable  bool
	FileError string
	ModTime   time.Time

	// Manageable is false when nothing can be applied from here — no
	// suricata-update, or no staging directory. The UI stays read-only rather
	// than pretending.
	Manageable bool
	Why        string
	// SensorLive is true only when the control socket answers. SensorDetail
	// explains the cases where it does not — and they are not the same case:
	// the console runs unprivileged and Suricata creates its socket 0660
	// root:root, so "cannot reach it" is normal and says nothing about the
	// sensor's health, while "no socket at all" means it is stopped. Reporting
	// both as "stopped" would send someone to restart a healthy sensor.
	SensorLive   bool
	SensorDetail string
	SocketPath   string
	UpdaterPath  string
	StagingPath  string
	ConfDirPath  string
	LastUpdate   time.Time
	AutoUpdate   bool
	UpdateHour   int
	AutoBlock    bool
	AutoBlockCap int

	// Pending is an apply that has been asked for and not yet reported back.
	// Stale means it has been waiting long enough that the privileged step is
	// probably not wired up.
	Pending      bool
	PendingSince time.Time
	Stale        bool

	LastRun store.RuleRun
	HasRun  bool

	// Drift counts, so a banner can say "3 changes waiting to be applied"
	// without the page loading every policy row.
	Waiting   int
	Refused   int
	Unknown   int
	Policies  int
	AutoRules int
}

// Status gathers it.
func (m *Manager) Status() (Status, error) {
	s := Status{
		RulesFile:   m.paths.RulesFile,
		SocketPath:  m.paths.Socket,
		StagingPath: m.paths.Staging,
		ConfDirPath: m.paths.ConfDir,
	}

	counts, err := m.store.RuleCounts()
	if err != nil {
		return s, err
	}
	s.RuleCounts = counts

	if info, err := suricata.Stat(m.paths.RulesFile); err != nil {
		s.FileError = err.Error()
	} else {
		s.ModTime = info.ModTime
		if f, err := os.Open(m.paths.RulesFile); err != nil {
			s.FileError = err.Error()
		} else {
			f.Close()
			s.Readable = true
		}
	}

	switch reach, err := suricata.NewControl(m.paths.Socket, 0).Probe(); reach {
	case suricata.ReachOK:
		s.SensorLive = true
		s.SensorDetail = "rules reload without a restart"
	case suricata.ReachDenied:
		// Expected on a normal install, and not a fault.
		s.SensorDetail = "the console cannot open the control socket (it is 0660 root:root) — the privileged apply step runs as root and can"
	case suricata.ReachRefused:
		s.SensorDetail = "the control socket is there but nothing is listening — suricata is stopped"
	default:
		s.SensorDetail = "no control socket — suricata is stopped, or unix-command is disabled in suricata.yaml"
		_ = err
	}
	updater := &suricata.Updater{Bin: m.paths.UpdateBin}
	if path, err := updater.Path(); err == nil {
		s.UpdaterPath = path
	}

	switch {
	case !s.Readable:
		s.Why = "meerkat cannot read " + m.paths.RulesFile + " — " + s.FileError
	case s.UpdaterPath == "":
		s.Why = "suricata-update is not installed, so the ruleset cannot be rebuilt from here"
	default:
		s.Manageable = true
	}

	if settings, ok, err := m.store.GetSettings(); err != nil {
		return s, err
	} else if ok {
		s.LastUpdate = settings.RulesLastUpdate
		s.AutoUpdate, s.UpdateHour = settings.RulesAutoUpdate, settings.RulesUpdateHour
		s.AutoBlock, s.AutoBlockCap = settings.AutoBlockEnabled, settings.AutoBlockMaxHour
	}

	pending, since, err := m.Pending()
	if err != nil {
		return s, err
	}
	s.Pending, s.PendingSince = pending, since
	s.Stale = pending && time.Since(since) > staleRequest

	run, hasRun, err := m.store.LastRuleRun("")
	if err != nil {
		return s, err
	}
	s.LastRun, s.HasRun = run, hasRun

	drifts, err := m.Drifts()
	if err != nil {
		return s, err
	}
	for _, d := range drifts {
		switch d.Status {
		case DriftPending:
			s.Waiting++
		case DriftRefused:
			s.Refused++
		case DriftUnknown:
			s.Unknown++
		}
	}

	policies, err := m.store.RulePolicies()
	if err != nil {
		return s, err
	}
	s.Policies = len(policies)
	for _, p := range policies {
		if p.AutoBlock {
			s.AutoRules++
		}
	}
	return s, nil
}
