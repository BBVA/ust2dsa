module Data.UbuntuSecurityTracker.CVE.Token
    ( Content (..)
    , Status (..)
    , Notes
    , Package
    , Release
    ) where

type Package = String
type Release = String
type Notes = String

data Status =
  -- Affected version does not exist in the archive
    DNE

  -- Still undecided
  | NEEDSTRIAGE

  -- Not vulnerable
  | NOTAFFECTED

  -- Vulnerable, but not important
  | IGNORED

  -- Package is vulnerable
  | NEEDED
  | ACTIVE
  | PENDING
  | DEFERRED

  -- Fixed
  | RELEASED
  | RELEASEDESM
  deriving (Show, Eq, Ord)



data Content = Metadata String String
             | ReleasePackageStatus Release Package Status (Maybe Notes)
             | Ignored String
             deriving (Show, Eq, Ord)
