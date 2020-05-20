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

#### Installation

```sh
sudo snap install ust2dsa
```

#### Usage

```sh
        ust2dsa                                 \
          --generic                             \
          --release=groovy                      \
          --release=focal                       \
          --release=eoan                        \
          --release=bionic                      \
          --release=xenial                      \
          --release=trusty                      \
          /path/to/git-repo/of/ubuntu-cve-tracker/active/CVE-*
```

## Data feed

This git repository has an orphan branch named `data`.  In this branch,
vulnerability information from the *Ubuntu CVE Tracker* is compiled in *debsecan*
format every **6 hours**.
