module Data.UbuntuSecurityTracker.CVE.Package
  ( Status(..)
  , Package(..)
  , mapStatus
  ) where

data Status
  = VULNERABLE String
  | NOTVULNERABLE String
  deriving (Show, Eq, Ord)

data Package =
  Package
    { release :: String
    , name :: String
    , status :: Status
    }
  deriving (Show, Eq, Ord)

mapStatus = undefined
