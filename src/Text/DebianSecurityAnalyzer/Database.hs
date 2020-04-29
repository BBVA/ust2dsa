module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE
import Data.List
import Data.Maybe

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } = n ++ ",," ++ d

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

renderDebsecanDB :: [CVE] -> String
renderDebsecanDB _ = "VERSION 1\n\n\n"
