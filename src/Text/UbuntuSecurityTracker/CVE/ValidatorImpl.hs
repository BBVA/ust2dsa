{-# LANGUAGE MultiWayIf #-}
{-|
Copyright 2020 Banco Bilbao Vizcaya Argentaria, S.A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-}

module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( honorToken
  , fillCVE
  ) where

import Control.Monad
import Data.UbuntuSecurityTracker.CVE
import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import Data.UbuntuSecurityTracker.CVE.Token
import Data.List (isInfixOf)

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
  | k == "CVSS" =
    if | "/AV:N/" `isInfixOf` v -> Right c {isRemote = Just True}
       | "/AV:" `isInfixOf` v -> Right c {isRemote = Just False}
       | otherwise -> Right c
  | otherwise = Right c
honorToken c (RPS r p s Nothing) = Right c
honorToken c@CVE {affected = aps} (RPS r p s cv) =
  Right $
  case P.mapStatus s cv of
    Nothing -> c
    Just st -> c {affected = P.Package r p st : aps}
