module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } = n ++ ",," ++ d

renderPackage :: String -> CVE -> Maybe String
renderPackage _ _ = Nothing
