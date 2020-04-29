module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE
import Data.List
import Data.Maybe

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } = n ++ ",," ++ d

renderPackage :: String       -- Release
              -> String       -- Package Name
              -> CVE          -- Vulnerability
              -> Maybe String -- Formatted Output
renderPackage _ _ CVE { affected = [] } = Nothing
renderPackage r p CVE { affected=aps } =
    Just $ intercalate "," [name, flags, unstable_version, other_versions]
  where
    name = p
    flags = "S   "
    unstable_version = fromMaybe "" $ getUnstableVersion p aps
    other_versions = unwords $ getOtherVersions p aps
