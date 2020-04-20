module Data.UbuntuCVE
    ( Status (..)
    , Content (..)
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

  -- Package is vulnerable
  | NEEDED
  | ACTIVE
  | IGNORED -- Very low priority
  | PENDING
  | DEFERRED

  -- Fixed
  | RELEASED
  | RELEASEDESM
  deriving (Show, Eq)
data Content = Metadata String String
             | ReleasePackageStatus Release Package Status (Maybe Notes)
             | Ignored String
             deriving (Show, Eq)
