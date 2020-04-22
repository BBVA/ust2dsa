module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( fillStaged
  ) where

import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

fillStaged :: [Token] -> Staged
fillStaged = fillStaged' emptyStaged


fillStaged' :: Staged -> [Token] -> Staged
fillStaged' s [] = s
fillStaged' s ((Ignored _):ps) = fillStaged' s ps
fillStaged' s ((Metadata k v):ps)
  | k == "Candidate"                 = fill s{name=Just v}
  | k == "Description"               = fill s{description=Just v}
  | k == "Priority" && v == "high"   = fill s{priority=Just H}
  | k == "Priority" && v == "medium" = fill s{priority=Just M}
  | k == "Priority" && v == "low"    = fill s{priority=Just L}
  | otherwise                        = fill s
  where fill s' = fillStaged' s' ps
