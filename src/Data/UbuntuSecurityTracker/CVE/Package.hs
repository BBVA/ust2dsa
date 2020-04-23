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

mapStatus :: T.Status -> Maybe String -> Maybe Status
mapStatus (T.NEEDED) (Just s) = Just $ VULNERABLE s
mapStatus (T.ACTIVE) (Just s) = Just $ VULNERABLE s
mapStatus (T.PENDING) (Just s) = Just $ VULNERABLE s
mapStatus (T.DEFERRED) (Just s) = Just $ VULNERABLE s
mapStatus (T.DNE) (Just s) = Just $ NOTVULNERABLE s
mapStatus (T.NEEDSTRIAGE) (Just s) = Just $ NOTVULNERABLE s
mapStatus (T.NOTAFFECTED) (Just s) = Just $ NOTVULNERABLE s
mapStatus (T.IGNORED) (Just s) = Just $ NOTVULNERABLE s
mapStatus (T.RELEASED) (Just s) = Just $ NOTVULNERABLE s
mapStatus (T.RELEASEDESM) (Just s) = Just $ NOTVULNERABLE s
