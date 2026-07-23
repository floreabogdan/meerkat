package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/floreabogdan/meerkat/internal/store"
	"github.com/floreabogdan/meerkat/internal/web"
)

// cmdPasswd sets an account's password from the console.
//
// Without it, a forgotten password means hand-writing a bcrypt hash into
// SQLite: meerkat has no password reset by email and nothing else can rewrite a
// credential. The console is reachable over an SSH tunnel on a box the operator
// already has root on, so the recovery path should be a command, not a database
// editor.
//
// It deliberately does not ask for the current password. This runs as root on
// the machine that owns the database — anyone who can run it can already read
// and rewrite that file directly, so demanding the old password would protect
// nothing and lock out the exact case the command exists for.
func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to meerkat's SQLite database")
	username := fs.String("username", "admin", "the account to change")
	password := fs.String("password", "", "the new password (if omitted, you'll be prompted — preferred, since flags land in shell history)")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	user, ok, err := st.GetUserByUsername(*username)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no account called %q — run \"meerkat init\" to create one", *username)
	}

	pw := *password
	if pw == "" {
		pw, err = promptPassword()
		if err != nil {
			return err
		}
	}
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := web.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := st.SetPassword(user.ID, hash); err != nil {
		return err
	}

	// Every existing session is signed out — there is none to keep, since this
	// runs from a terminal rather than a browser. A password reset is usually a
	// response to the old one being compromised, and leaving live sessions
	// behind would mean the change did nothing for the case it was made for.
	if err := st.DeleteUserSessionsExcept(user.ID, ""); err != nil {
		return fmt.Errorf("password changed, but existing sessions could not be ended: %w", err)
	}

	_ = st.InsertSystemAudit(store.AuditSettings,
		"password reset for "+user.Username+" from the console; every session was signed out")

	fmt.Fprintf(os.Stdout, "password changed for %s — every existing session has been signed out\n", user.Username)
	return nil
}
