{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Prelude hiding (readFile)
import Options.Generic
import System.IO (stdout, stderr, hPutStrLn, hPutStr)

import Control.Monad
import Data.Bifunctor
import Data.DebianSecurityAnalyzer.CVE (CVE, mapCVE)
import Data.Either
import System.Exit (exitFailure)
import Text.DebianSecurityAnalyzer.Database (renderDebsecanDB)
import Text.Parsec (parse)
import Text.Parsec.String (Parser(..), parseFromFile)
import Text.UbuntuSecurityTracker.CVE (parseAndValidate)
import Text.UbuntuSecurityTracker.CVE.Parser (cveParser)
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl (fillCVE)
import System.IO.Strict (readFile)

data Args =
  Args String [String]
  deriving (Generic, Show)

instance ParseRecord Args

main = do
  (Args release files) <- getRecord "Ubuntu Security Tracker To Debsecan File"

  parsed <- mapM parseFile files
  let (errors, cves) = partitionEithers parsed

  forM_ errors $ hPutStrLn stderr
  hPutStr stdout $ renderDebsecanDB release cves

  where
    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = readFile fn >>= return . parseAndValidate fn
