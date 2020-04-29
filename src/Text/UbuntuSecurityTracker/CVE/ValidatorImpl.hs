{-# LANGUAGE MultiWayIf #-}

module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( honorToken
  , fillCVE
  ) where

import Control.Monad
import Data.UbuntuSecurityTracker.CVE
import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import Data.UbuntuSecurityTracker.CVE.Token

fillCVE :: [Token] -> Either String CVE
fillCVE = foldM honorToken emptyCVE

-- TODO: Fill isRemote field when a CVSS parser is available
honorToken :: CVE -> Token -> Either String CVE
honorToken c (Ignored _) = Right c
honorToken c (Metadata k v)
  | k == "Candidate" = Right c {name = Just v}
  | k == "Description" = Right c {description = Just v}
  | k == "Priority" =
    if | v == "high" -> Right c {priority = Just H}
       | v == "medium" -> Right c {priority = Just M}
       | v == "low" -> Right c {priority = Just L}
       | v == "negligible" -> Right c {priority = Just L}
       | v == "untriaged" -> Right c {priority = Nothing}
       | otherwise -> Left $ "unknown priority value '" ++ v ++ "'"
  | otherwise = Right c
honorToken c (RPS r p s Nothing) = Right c
honorToken c@CVE {affected = aps} (RPS r p s cv) =
  Right $
  case P.mapStatus s cv of
    Nothing -> c
    Just st -> c {affected = P.Package r p st : aps}
