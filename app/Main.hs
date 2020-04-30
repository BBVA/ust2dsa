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
import System.IO (stdout, stderr, hPutStrLn, putStr, IOMode(..), withFile)

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
import Codec.Compression.Zlib (compress)
import Data.ByteString.Lazy (hPutStr)
import Data.Text.Lazy (pack)
import Data.Text.Lazy.Encoding (encodeUtf8)

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
  
  let releases = release args
  let files = cves args
  let buildGeneric = generic args

  parsed <- mapM parseFile files
  let (errors, cves) = partitionEithers parsed
  let render r = renderDebsecanDB r cves

  forM_ errors $ hPutStrLn stderr
  forM_ releases $ \x -> writeOutput x (render x)
  when buildGeneric (writeOutput "GENERIC" (render ""))

  where
    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = parseAndValidate fn <$> readFile fn

    writeOutput :: FilePath -> String -> IO ()
    writeOutput fp s = withFile fp WriteMode (\h -> hPutStr h ((compress . encodeUtf8 . pack) s))
        
