# Purpose

Owns JVM unit tests for app logic that can run without device/emulator.

# Ownership

- Tests under `app/src/test/java/`

# Local Contracts

- Cover non-trivial logic changes with one focused regression test.
- Keep tests deterministic and fast.
- A hand-rolled DAO fake must key its rows the way the real table does. `FakeEmailDao` is keyed on
  (folder, messageId) for that reason: keyed on the id alone it silently reproduced the
  folder-collision bug it was supposed to catch, and every test still passed. Where the SQL itself
  is the thing under test, the authority is an instrumentation test against real Room
  (`EmailDaoFolderScopeTest`, `EmailDaoClearDecryptedTest`).

# Work Guidance

- Prefer pure function tests for keyword tabbing/filtering behavior.
- Avoid network or Android framework dependencies in JVM unit tests.

# Verification

- Run `testDebugUnitTest` after unit test updates.

# Child DOX Index

- No child AGENTS.md files.

