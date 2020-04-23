module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( fillStaged
  ) where

import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

fillStaged :: [Token] -> Staged
fillStaged = foldl honorToken emptyStaged

-- TODO: Fill isRemote field when a CVSS parser is available
honorToken :: Staged -> Token -> Staged
honorToken s (Ignored _) = s
honorToken s (Metadata k v)
  | k == "Candidate"                 = s{name=Just v}
  | k == "Description"               = s{description=Just v}
  | k == "Priority" && v == "high"   = s{priority=Just H}
  | k == "Priority" && v == "medium" = s{priority=Just M}
  | k == "Priority" && v == "low"    = s{priority=Just L}
  | otherwise                        = s
