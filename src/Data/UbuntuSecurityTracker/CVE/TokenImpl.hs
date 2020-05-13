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

module Data.UbuntuSecurityTracker.CVE.TokenImpl
  ( Token(..)
  , Status(..)
  , Notes
  , Package
  , Release
  ) where

import GHC.Generics

type Package = String

type Release = String

type Notes = String

data Status
  -- Affected version does not exist in the archive
  = DNE
  -- Still undecided
  | NEEDSTRIAGE
  -- Not vulnerable
  | NOTAFFECTED
  -- Vulnerable, but not important
  | IGNORED
  -- Package is vulnerable
  | NEEDED
  | ACTIVE
  | PENDING
  | DEFERRED
  -- Fixed
  | RELEASED
  | RELEASEDESM
  deriving (Generic, Show, Eq, Ord)

data Token
  = Metadata String String
  | RPS Release Package Status (Maybe Notes)
  | Ignored String
  deriving (Show, Eq, Ord)
