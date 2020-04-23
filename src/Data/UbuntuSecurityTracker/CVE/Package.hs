module Data.UbuntuSecurityTracker.CVE.Package
  ( Status(..)
  , Package(..)
  , mapStatus
  ) where

import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.Versions (versioning)
import Data.Text (pack)

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

isValidVersion :: String -> Bool
isValidVersion s =
  case versioning (pack s) of
    Right _ -> True
    Left _ -> False

mapStatus :: T.Status -> Maybe String -> Maybe Status
mapStatus _ Nothing = Nothing
mapStatus s (Just v)
  | isValidVersion v = Just $ mapStatus' s v
  | otherwise = Nothing

mapStatus' :: T.Status -> String -> Status
mapStatus' (T.NEEDED) s = VULNERABLE s
mapStatus' (T.ACTIVE) s = VULNERABLE s
mapStatus' (T.PENDING) s = VULNERABLE s
mapStatus' (T.DEFERRED) s = VULNERABLE s
mapStatus' (T.DNE) s = NOTVULNERABLE s
mapStatus' (T.NEEDSTRIAGE) s = NOTVULNERABLE s
mapStatus' (T.NOTAFFECTED) s = NOTVULNERABLE s
mapStatus' (T.IGNORED) s = NOTVULNERABLE s
mapStatus' (T.RELEASED) s = NOTVULNERABLE s
mapStatus' (T.RELEASEDESM) s = NOTVULNERABLE s
