{-# LANGUAGE OverloadedStrings#-}

module Data.UbuntuSecurityTracker.CVE.Package
  ( Status(..)
  , isVulnerable
  , Package(..)
  , getVersion
  , mapStatus
  ) where

import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.Either (isRight)
import Data.Versions (versioning)
import Data.Text (pack, replace)

data Status
  = VULNERABLE String
  | NOTVULNERABLE String
  deriving (Show, Eq, Ord)

isVulnerable :: Status -> Bool
isVulnerable (VULNERABLE _) = True
isVulnerable (NOTVULNERABLE _) = False

getVersion :: Status -> String
getVersion (VULNERABLE r) = r
getVersion (NOTVULNERABLE r) = r

data Package =
  Package
    { release :: String
    , name :: String
    , status :: Status
    }
  deriving (Show, Eq, Ord)


isValidVersion :: String -> Bool
isValidVersion = isRight . versioning . replace "~" "+" . pack

mapStatus :: T.Status -> Maybe String -> Maybe Status
mapStatus _ Nothing = Nothing
mapStatus s (Just v)
  | isValidVersion v = Just $ mapStatus' s v
  | otherwise = Nothing

mapStatus' :: T.Status -> String -> Status
mapStatus' T.NEEDED = VULNERABLE
mapStatus' T.ACTIVE  = VULNERABLE
mapStatus' T.PENDING = VULNERABLE
mapStatus' T.DEFERRED = VULNERABLE
mapStatus' T.DNE = NOTVULNERABLE
mapStatus' T.NEEDSTRIAGE = NOTVULNERABLE
mapStatus' T.NOTAFFECTED = NOTVULNERABLE
mapStatus' T.IGNORED = NOTVULNERABLE
mapStatus' T.RELEASED = NOTVULNERABLE
mapStatus' T.RELEASEDESM = NOTVULNERABLE

