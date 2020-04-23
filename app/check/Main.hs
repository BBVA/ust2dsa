{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Generic
import Text.UbuntuSecurityTracker.CVE.Parser

main = do
  files <- getRecord "CVE File Checker"
  mapM (parseFile cveParser) (files :: [String])
