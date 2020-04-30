{-# LANGUAGE DeriveDataTypeable #-}

module Main where

import Prelude hiding (readFile)
import System.IO (stdout, stderr, hPutStrLn, hPutStr, putStr)

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
import System.Console.CmdArgs.Implicit

data ArgParser =
  ArgParser
    { check :: Bool
    , manifest :: String
    , release :: [String]
    , generic :: Bool
    , cves :: [String]
    }
  deriving (Show, Data, Typeable)

argparser =
  ArgParser
    { check = def &= help "Only check CVE files for errors"
    , manifest = def &= help "Base URI to Ubuntu's release manifest"
    , release = def &= help "Ubuntu release codename"
    , generic = def &= help "Build a GENERIC database"
    , cves = def &= args
    } &= program "ust2dsa"
      &= summary "Ubuntu Security Tracker ...."

main = do
  args <- cmdArgs argparser
  
  let release = ""
  let files = cves args

  parsed <- mapM parseFile files
  let (errors, cves) = partitionEithers parsed

  forM_ errors $ hPutStrLn stderr
  putStr $ renderDebsecanDB release cves

  where
    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = parseAndValidate fn <$> readFile fn
