{-# LANGUAGE MultiWayIf #-}

module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( honorToken
  , fillCVE
  ) where

import Control.Monad
import Data.UbuntuSecurityTracker.CVE
import Data.UbuntuSecurityTracker.CVE.Token

fillCVE :: [Token] -> Either String CVE
fillCVE = foldM honorToken emptyCVE

-- TODO: Fill isRemote field when a CVSS parser is available
honorToken :: CVE -> Token -> Either String CVE
honorToken s (Ignored _) = Right s
honorToken s (Metadata k v)
  | k == "Candidate" = Right s {name = Just v}
  | k == "Description" = Right s {description = Just v}
  | k == "Priority" =
    if | v == "high" -> Right s {priority = Just H}
       | v == "medium" -> Right s {priority = Just M}
       | v == "low" -> Right s {priority = Just L}
       | otherwise -> Left "unknown priority value"
  | otherwise = Right s
honorToken s (RPS r p st Nothing) = Right s
