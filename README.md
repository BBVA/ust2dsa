# UST2DSA

![License check](https://github.com/BBVA/ust2dsa/workflows/License%20check/badge.svg)
![Haskell CI](https://github.com/BBVA/ust2dsa/workflows/Haskell%20CI/badge.svg)


This tool aims to enable Ubuntu users to leverage Debian's [`debsecan`][DEBSECAN]
vulnerability analysis and reporting tool.

Feeding from the [Ubuntu CVE Tracker][UCVET], it produces vulnerability databases
suitable for `debsecan`.

[DEBSECAN]: https://gitlab.com/fweimer/debsecan
[UCVET]: https://people.canonical.com/~ubuntu-security/cve/

## Usage

### For end-users

#### Ubuntu since eoan (19.10)

```sh
debsecan --suite $(lsb_release --codename --short) --source https://raw.githubusercontent.com/BBVA/ust2dsa/data/
```

#### Ubuntu (any release)
CAVEAT EMPTOR: The list of available fixes for your particular system won't be produced in this case.

```sh
debsecan --source https://raw.githubusercontent.com/BBVA/ust2dsa/data/
```


### For database maintainers

**TODO**


## debsecan database format

Since we haven't been able to find proper documentation for this format,
we are going to do it ourselves distilling the source code of debsecan.


The database file starts with a version header:

```
VERSION 1
```

Note: any other string will cause the program to exit.

The database has three sections, separated by an empty line.


### Section: List of vulnerabilities

Contains lines with three comma-separated fields.

The fields are:

* `name`

* `flags`

  Unused by `debsecan`.

* `desc`

  Description of the vulnerability truncated to 74 characters.


### Section: List of vulnerable packages

Contains lines with five comma-separated fields.

* `package`

  Name of the affected package.

* `vnum`

  Vulnerability identifier.  It is an offset from the beginning of the first
  section (starting at 0).

* `flags`

  It is a field composed of several upper case characters and symbols.

  * The first character can be either `B` or something else.  If, and only if,
    this flag is `B`, the affected package is a binary package.

  * The second flag is named **Urgency**.  It has four valid values:
    - `L`: Low.
    - `M`: Medium (can't talk to the spirits, though).
    - `H`: High.
    - ` `: Undefined.

  * The third flag is named **Remote**. It has three valid values:
    - `R`: Remotely exploitable.
    - ` `: Not remotely exploitable.
    - `?`: Undefined, but assumed to be not remotely exploitable.

  * The fourth flag is named **Fix Available**.
    - `F`: There is a fix available for the current suite (N/A in `GENERIC` db).
    - *anything else*: There is no known fix available yet.

  Note: The flags are positional, so all of them must be present.  Typically,
  many of them will be simply space chars.


* `unstable_version`

  This field can contain a single version.  It represents the first version in
  the unstable suite that has a fix for the reported vulnerability.

  So, any version strictly less than this one and not listed in `other_versions`
  (see below) is to be considered vulnerable.


* `other_versions`

  It is a list of space-separated versions.  These versions are not vulnerable,
  and can belong to any suite.


### Section: Source to Binary map

Comma-separated list of maps from source to binary packages.  Empty for the
`GENERIC` database.


## Database Distribution

All this data is served through this service:

```
https://security-tracker.debian.org/tracker/debsecan/release/1/<DBNAME>
```

where `<DBNAME>` can by either `GENERIC` or a valid lower-case suite name, such
us: `bullseye`, `buster` or `stretch`.
