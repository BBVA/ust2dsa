module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE

renderVulnerability :: CVE -> String
renderVulnerability CVE { name=""
                        , description=""
                        , priority=Nothing
                        , isRemote=Nothing
                        , affected=[] } = ",,"
renderVulnerability _ = "foo,,bar"
