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
module Text.DebianSecurityAnalyzer.DatabaseImpl
  ( renderVulnerability
  , renderPackage
  , renderDebsecanDB
  , renderSource
  ) where

import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP
import Data.Bool
import Data.List
import Data.Map (Map)
import Data.Map.Strict (toList)
import Data.Maybe

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } =
    let saneDescription = fmap replaceNewLines d
    in n ++ ",," ++ saneDescription
  where
    replaceNewLines :: Char -> Char
    replaceNewLines c = bool ' ' c ('\n' /= c)

renderPackage :: String       -- Release
              -> Int          -- Vulnerability Index (section offset)
              -> String       -- Package Name
              -> CVE          -- Vulnerability
              -> Maybe String -- Formatted Output
renderPackage _ _ _ CVE { affected = [] } = Nothing
renderPackage r o p CVE { affected = aps
                        , priority = pri
                        , isRemote = rmt } =
    Just $ intercalate "," [name, show o, flags, unstable_version, other_versions]
  where
    name = p
    flags = [ 'S', getFlagUrgency pri, getFlagIsRemote rmt, getFlagIsFixAvailable r p aps ]
    unstable_version = fromMaybe "" $ getUnstableVersion p aps
    other_versions = unwords $ getOtherVersions p aps

renderSource :: (String, [String]) -> String
renderSource (srcPackage, binPackages) = srcPackage ++ "," ++ (intercalate " " binPackages)

renderDebsecanDB :: String -> [CVE] -> Map String [String] -> String
renderDebsecanDB r cs srcs = "VERSION 1\n" ++ sections
  where
    sections = intercalate "\n\n" [ vulnerabilities, affected, sources ]
    vulnerabilities = intercalate "\n" $ fmap renderVulnerability cs
    affected = intercalate "\n" renderedAffected
    renderedAffected = do
      (i, c@CVE { affected = aps }) <- zip [0..] cs
      p <- nub $ UP.name <$> aps
      maybe [] return (renderPackage r i p c)
    sources = intercalate "\n" $ fmap renderSource (toList srcs)
