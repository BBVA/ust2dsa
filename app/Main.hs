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

{-# LANGUAGE DeriveDataTypeable #-}

module Main where

import Prelude hiding (readFile)
import System.IO (IOMode(..), hPutStrLn, stderr, withFile)

import qualified Codec.Compression.Zlib as Zlib
import Control.Monad (forM_, mapM, when)
import Data.ByteString.Lazy (hPutStr)
import Data.Either (partitionEithers)
import Data.Text.Lazy (pack)
import Data.Text.Lazy.Encoding (encodeUtf8)
import System.Console.CmdArgs.Implicit
import System.Exit (die)
import System.IO.Strict (readFile)

import Data.UbuntuSecurityTracker.CVE.Token
import Control.Monad.State
import qualified Data.Map.Strict as Map
import Text.UbuntuSecurityTracker.CVE.Parser
import Codec.Compression.Lzma
import Network.Download
import Data.Either
import Data.Bifunctor
import Data.ByteString.Lazy (hPutStr, fromStrict, toStrict)
import Data.ByteString.Char8 (unpack)
import Data.List.Split

import Data.DebianSecurityAnalyzer.CVE (CVE, affected, name)
import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import Text.DebianSecurityAnalyzer.Database (renderDebsecanDB)
import Text.UbuntuSecurityTracker.CVE (parseAndValidate)
import Text.UbuntuSecurityTracker.CVE.Parser (cveParser)
import Text.UbuntuSecurityTracker.CVE.Validator (fillCVE)

data Source = Source { package :: String
                     , binary :: [String]
                     } deriving (Show)

fromSource :: Source -> (String, [String])
fromSource (Source p bs) = (p, bs)

parseSource :: [Token] -> State String [Source]
parseSource [] = pure []
parseSource ((Metadata k v):xs)
    | k == "Package" = do put v
                          parseSource xs
    | k == "Binary" = do package <- get
                         rest <- parseSource xs
                         let r = (Source {package=package, binary=(filter (not . null) $ splitOneOf ",\n " v)}):rest
                         return r
    | otherwise = parseSource xs
parseSource (_:xs) = parseSource xs

fromTokens :: [String] -> [Token] -> [(String, [String])]
fromTokens ps ts = filter (\(p, _) -> p `elem` ps) $ fromSource <$> evalState (parseSource ts) ""

sources :: [[(String, [String])]] -> Map.Map String [String]
sources = Map.fromList . concat

sourcesFromURIs :: [String] -> [String] -> IO (Either [String] (Map.Map String [String]))
sourcesFromURIs vulnerables fss =
    do scs <- mapM (sourcesFromURI vulnerables) fss
       let (errors, results) = partitionEithers scs
       if null errors
       then return . Right $ sources results
       else return $ Left errors

sourcesFromURI :: [String] -> String -> IO (Either String [(String, [String])])
sourcesFromURI vulnerables uri = do
    content <- openURI uri
    let sourceFile = bimap (\err -> uri ++ " : " ++ err) decompressToString content
    let parsed = sourceFile >>= parseWithErrors
    return $ second (fromTokens vulnerables) parsed
  where
    decompressToString = unpack . toStrict . decompress . fromStrict

urisFromSuite :: String -> String -> [String]
urisFromSuite base suite = do part1 <- ["", "-security", "-updates", "-proposed", "-backports"]
                              part2 <- ["main", "universe", "multiverse", "restricted"]
                              return $ base <> "/" <> suite <> part1 <> "/" <> part2 <> "/source/Sources.xz"

getSuiteSource :: [String] -> String -> IO (Either [String] (Map.Map String [String]))
getSuiteSource packages suite = do
    let urls = urisFromSuite "http://ftp.ubuntu.com/ubuntu/dists" suite
    dict <- sourcesFromURIs packages urls
    return dict


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
  forM_ releases $ writeDBForRelease cves

  when buildGeneric $ writeOutput "GENERIC" $ renderDebsecanDB "" cves Map.empty

  where
    
    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = parseAndValidate fn <$> readFile fn

    writeOutput :: FilePath -> String -> IO ()
    writeOutput fp s =
      let putCompressed h = hPutStr h $ (Zlib.compress . encodeUtf8 . pack) s
       in withFile fp WriteMode putCompressed

    packages :: [CVE] -> [String]
    packages cves = P.name <$> (concat $ affected <$> cves)

    writeDBForRelease :: [CVE] -> String -> IO ()
    writeDBForRelease cves release = do
        let vulnerablePackages = packages cves
        result <- getSuiteSource vulnerablePackages release
        mapM_ (hPutStrLn stderr) $ fromLeft [] result
        writeOutput release $ renderDebsecanDB release cves $ fromRight (Map.empty) result
