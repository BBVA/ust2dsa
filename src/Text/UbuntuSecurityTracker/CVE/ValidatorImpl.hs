module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( fillStaged
  ) where

import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

fillStaged :: [Token] -> Staged
fillStaged = fillStaged' emptyStaged


fillStaged' :: Staged -> [Token] -> Staged
fillStaged' s [] = s
fillStaged' s ((Metadata "Candidate" v):ps) = fillStaged' s{name=Just v} ps
fillStaged' s ((Ignored _):ps) = fillStaged' s ps
