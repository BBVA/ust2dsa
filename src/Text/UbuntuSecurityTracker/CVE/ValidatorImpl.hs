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
  | k == "Candidate"   = fillStaged' s{name=Just v} ps
  | k == "Description" = fillStaged' s{description=Just v} ps
  | otherwise          = fillStaged' s ps
