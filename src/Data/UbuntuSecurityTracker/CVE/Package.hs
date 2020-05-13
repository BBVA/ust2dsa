{-|
Copyright 2020 Banco Bilbao Vizcaya Argentaria, S.A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-}

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

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
import GHC.Generics

data Status
  = VULNERABLE String
  | NONVULNERABLE String
  deriving (Generic, Show, Eq, Ord)

isVulnerable :: Status -> Bool
isVulnerable (VULNERABLE _) = True
isVulnerable (NONVULNERABLE _) = False

getVersion :: Status -> String
getVersion (VULNERABLE r) = r
getVersion (NONVULNERABLE r) = r

data Package =
  Package
    { release :: String
    , name :: String
    , status :: Status
    }
  deriving (Generic, Show, Eq, Ord)


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
mapStatus' T.DNE = NONVULNERABLE
mapStatus' T.NEEDSTRIAGE = NONVULNERABLE
mapStatus' T.NOTAFFECTED = NONVULNERABLE
mapStatus' T.IGNORED = NONVULNERABLE
mapStatus' T.RELEASED = NONVULNERABLE
mapStatus' T.RELEASEDESM = NONVULNERABLE

