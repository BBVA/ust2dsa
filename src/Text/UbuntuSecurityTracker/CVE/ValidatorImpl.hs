module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( fillStaged
  ) where

import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

fillStaged :: [Token] -> Staged
fillStaged [] = emptyStaged
