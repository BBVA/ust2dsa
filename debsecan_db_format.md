# debsecan database format

Since we haven't been able to find proper documentation for this format,
we are going to do it ourselves distilling the source code of `debsecan`.

## Structure

The database file starts with a version header:

```text
VERSION 1
```

Note: any other string will cause the program to exit.

The database has three sections, separated by an empty line.

Also note that all three sections are lexicographically ordered.


### Section: List of vulnerabilities

Contains lines with three comma-separated fields.

The fields are:

- `name`

- `flags`

  Unused by `debsecan`.

- `desc`

  Description of the vulnerability truncated to 74 characters.

### Section: List of vulnerable packages

Contains lines with five comma-separated fields.

- `package`

  Name of the affected package.

- `vnum`

  Vulnerability identifier. It is an offset from the beginning of the first
  section (starting at 0).

- `flags`

  It is a field composed of several upper case characters and symbols.

  - The first character can be either `B` or something else. If, and only if,
    this flag is `B`, the affected package is a binary package.

  - The second flag is named **Urgency**. It has four valid values:

    - `L`: Low.
    - `M`: Medium (can't talk to the spirits, though).
    - `H`: High.
    - `␣`: Undefined.

  - The third flag is named **Remote**. It has three valid values:

    - `R`: Remotely exploitable.
    - `␣`: Not remotely exploitable.
    - `?`: Undefined, but assumed to be not remotely exploitable.

  - The fourth flag is named **Fix Available**.

    - `F`: There is a fix available for the current suite (N/A in `GENERIC` db).
    - _anything else_: There is no known fix available yet.

  Note: The flags are positional, so all of them must be present. Typically,
  many of them will be simply space chars.

- `unstable_version`

  This field can contain a single version. It represents the first version in
  the unstable suite that has a fix for the reported vulnerability.

  So, any version strictly less than this one and not listed in `other_versions`
  (see below) is to be considered vulnerable.

- `other_versions`

  It is a list of space-separated versions. These versions are not vulnerable,
  and can belong to any suite.

### Section: Source to Binary map

Comma-separated list of maps from source to binary packages. Empty for the
`GENERIC` database.

## Database Distribution

All this data is served through this service:

```text
https://security-tracker.debian.org/tracker/debsecan/release/1/<DBNAME>
```

where `<DBNAME>` can by either `GENERIC` or a valid lower-case suite name, such
us: `bullseye`, `buster` or `stretch`.
