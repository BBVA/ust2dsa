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
module Data.DebianSecurityAnalyzer.CVE where

import Control.Applicative
import Data.Bool
import Data.Foldable
import Data.List
import Data.Maybe
import Data.Maybe.HT
import Data.Monoid
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

data CVE =
  CVE
    { name :: String
    , description :: String
    , priority :: Maybe U.Priority
    , isRemote :: Maybe Bool
    , affected :: [UP.Package]
    }
  deriving (Show, Eq)

mapCVE :: U.CVE -> Either String CVE
mapCVE U.CVE { U.name = Just n
             , U.description = Just d
             , U.priority = p
             , U.isRemote = r
             , U.affected = aps
             } = Right $ CVE n d p r aps
mapCVE U.CVE {U.name = Nothing, U.description = Nothing} =
  Left "CVE identifier and description missing"
mapCVE U.CVE {U.name = Nothing} = Left "CVE identifier missing"
mapCVE U.CVE {U.description = Nothing} = Left "CVE description missing"

combineFilters :: [a -> Bool] -> a -> Bool
combineFilters filters x = and (filters <*> pure x)

getUnstableVersion :: String -> [UP.Package] -> Maybe String
getUnstableVersion p aps =
  let develPackages = filter (isVulnerableRelease "devel") aps
      upstreamPackages = filter (isVulnerableRelease "upstream") aps
   in firstVersion develPackages <|> firstVersion upstreamPackages
  where
    firstVersion :: [UP.Package] -> Maybe String
    firstVersion xs = UP.getVersion . UP.status <$> listToMaybe xs
    isVulnerableRelease :: String -> (UP.Package -> Bool)
    isVulnerableRelease r =
      combineFilters
        [ (== p) . UP.name
        , not . UP.isVulnerable . UP.status
        , (== r) . UP.release
        ]

getOtherVersions :: String -> [UP.Package] -> [String]
getOtherVersions p aps =
  let stablePackages = filter isStableAndVulnerable aps
   in nub $ version <$> stablePackages
  where
    version :: UP.Package -> String
    version = UP.getVersion . UP.status
    isStableAndVulnerable :: UP.Package -> Bool
    isStableAndVulnerable =
      combineFilters
        [ (== p) . UP.name
        , not . UP.isVulnerable . UP.status
        , (/= "devel") . UP.release
        , (/= "upstream") . UP.release
        ]

getFlagUrgency :: Maybe U.Priority -> Char
getFlagUrgency = maybe ' ' (head . show)

getFlagIsRemote :: Maybe Bool -> Char
getFlagIsRemote = maybe '?' (bool ' ' 'R')

getFlagIsFixAvailable :: String -> String -> [UP.Package] -> Char
getFlagIsFixAvailable r p aps =
  if any isFixed aps
    then 'F'
    else ' '
  where
    isFixed =
      combineFilters
        [ (== r) . UP.release
        , (== p) . UP.name
        , not . UP.isVulnerable . UP.status
        ]
