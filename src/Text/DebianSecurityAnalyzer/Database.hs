module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } = n ++ ",," ++ d

renderPackage :: String       -- Release
              -> String       -- Package Name
              -> CVE          -- Vulnerability
              -> Maybe String -- Formatted Output
renderPackage _ _ CVE { affected = [] } = Nothing
renderPackage r p CVE { affected=aps } =
  case getUnstableVersion p aps of
    Just v -> Just (p ++ ",S   ," ++ v ++ ",")
    Nothing -> Just (p ++ ",S   ,,")
