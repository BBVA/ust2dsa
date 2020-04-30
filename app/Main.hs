{-# LANGUAGE DeriveDataTypeable #-}
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

module Main where

import Prelude hiding (readFile)
import System.IO (IOMode(..), hPutStrLn, stderr, withFile)

import Codec.Compression.Zlib (compress)
import Control.Monad (forM_, mapM, when)
import Data.ByteString.Lazy (hPutStr)
import Data.Either (partitionEithers)
import Data.Text.Lazy (pack)
import Data.Text.Lazy.Encoding (encodeUtf8)
import System.Console.CmdArgs.Implicit
import System.Exit (die)
import System.IO.Strict (readFile)

import Data.DebianSecurityAnalyzer.CVE (CVE)
import Text.DebianSecurityAnalyzer.Database (renderDebsecanDB)
import Text.UbuntuSecurityTracker.CVE (parseAndValidate)
import Text.UbuntuSecurityTracker.CVE.Parser (cveParser)
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl (fillCVE)


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
    { check = def &= help "Only check CVE cveFiles for errors"
    , manifest = def &= help "Base URI to Ubuntu's release manifest"
    , release = def &= help "Ubuntu release codename"
    , generic = def &= help "Build a GENERIC database"
    , cves = def &= args
    } &= program "ust2dsa"
      &= summary "Ubuntu Security Tracker ...."

main = do
  args <- cmdArgs argparser
  
  let releases = release args
  let cveFiles = cves args
  let buildGeneric = generic args

  when (null cveFiles) $ die "You must specify at least one CVE source file"
  when (null releases && not buildGeneric) $ die "You must specify at least one release to build or GENERIC"

  (errors, cves) <- partitionEithers <$> mapM parseFile cveFiles

  forM_ errors   $ hPutStrLn stderr
  forM_ releases $ \x -> writeOutput x $ renderDebsecanDB x cves
  when buildGeneric $ writeOutput "GENERIC" $ renderDebsecanDB "" cves

  where
    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = parseAndValidate fn <$> readFile fn

    writeOutput :: FilePath -> String -> IO ()
    writeOutput fp s =
      let putCompressed h = hPutStr h $ (compress . encodeUtf8 . pack) s
       in withFile fp WriteMode putCompressed
