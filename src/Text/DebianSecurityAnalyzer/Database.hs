module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE

renderVulnerability :: CVE -> String
renderVulnerability CVE { name=n
                        , description=d
                        , priority=Nothing
                        , isRemote=Nothing
                        , affected=[] } = n ++ ",," ++ d
renderVulnerability _ = "foo,,bar"
