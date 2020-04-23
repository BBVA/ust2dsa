module Data.UbuntuSecurityTracker.CVE.Token
  ( Token(..)
  , Status(..)
  , Notes
  , Package
  , Release
  ) where

type Package = String

type Release = String

type Notes = String

data Status
  -- Affected version does not exist in the archive
  = DNE
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

data Token
  = Metadata String String
  | RPS Release Package Status (Maybe Notes)
  | Ignored String
  deriving (Show, Eq, Ord)
