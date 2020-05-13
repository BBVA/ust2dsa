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

{-# LANGUAGE DeriveGeneric #-}

module Data.UbuntuSecurityTracker.CVE
  ( CVE(..)
  , Priority(..)
  , emptyCVE
  ) where

import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import GHC.Generics

data Priority
  = L
  | M
  | H
  deriving (Generic, Show, Eq, Ord)

data CVE =
  CVE
    { name :: Maybe String
    , description :: Maybe String
    , priority :: Maybe Priority
    , isRemote :: Maybe Bool
    , affected :: [P.Package]
    }
  deriving (Show, Eq)

emptyCVE =
  CVE
    { name = Nothing
    , description = Nothing
    , priority = Nothing
    , isRemote = Nothing
    , affected = []
    }
