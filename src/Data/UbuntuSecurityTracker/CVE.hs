module Data.UbuntuSecurityTracker.CVE
  ( CVE(..)
  , Priority(..)
  , emptyCVE
  ) where

import qualified Data.UbuntuSecurityTracker.CVE.Package as P

data Priority
  = L
  | M
  | H
  deriving (Show, Eq, Ord)

data CVE =
  CVE
    { name :: Maybe String
    , description :: Maybe String
    , priority :: Maybe Priority
    , isRemote :: Maybe Bool
    , affected :: [P.Package]
    }
  deriving (Show, Eq)

emptyCVE =
  CVE
    { name = Nothing
    , description = Nothing
    , priority = Nothing
    , isRemote = Nothing
    , affected = []
    }
