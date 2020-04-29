module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n
                        , description = d
                        , priority = _
                        , isRemote = _
                        , affected = _ } = n ++ ",," ++ d
