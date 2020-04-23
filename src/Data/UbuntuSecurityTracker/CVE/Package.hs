module Data.UbuntuSecurityTracker.CVE.Package
  ( Status(..)
  , Package(..)
  , mapStatus
  ) where

import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))

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

mapStatus :: T.Status -> Maybe String -> Status
mapStatus (T.NEEDED) (Just s) = VULNERABLE s
mapStatus (T.ACTIVE) (Just s) = VULNERABLE s
mapStatus (T.PENDING) (Just s) = VULNERABLE s
mapStatus (T.DEFERRED) (Just s) = VULNERABLE s
mapStatus (T.DNE) (Just s) = NOTVULNERABLE s
mapStatus (T.NEEDSTRIAGE) (Just s) = NOTVULNERABLE s
mapStatus (T.NOTAFFECTED) (Just s) = NOTVULNERABLE s
mapStatus (T.IGNORED) (Just s) = NOTVULNERABLE s
mapStatus (T.RELEASED) (Just s) = NOTVULNERABLE s
mapStatus (T.RELEASEDESM) (Just s) = NOTVULNERABLE s
