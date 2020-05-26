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
module Text.UbuntuSources.ParserImpl where

import Codec.Compression.Lzma (decompress)
import qualified Data.Map.Strict as Map
import Network.Download (openURI)
import Data.Either (partitionEithers)
import Data.List.Split (splitOneOf)
import Data.Bifunctor (second, bimap)
import Control.Monad.State (State(..), evalState, get, put)
import Data.ByteString.Lazy (fromStrict, toStrict)
import Data.ByteString.Char8 (unpack)
import Text.UbuntuSecurityTracker.CVE.Parser (parseWithErrors)
import Data.UbuntuSecurityTracker.CVE.Token (Token(..))

data Source =
  Source
    { package :: String
    , binary :: [String]
    }
  deriving (Show)

fromSource :: Source -> (String, [String])
fromSource (Source p bs) = (p, bs)

parseSource :: [Token] -> State String [Source]
parseSource [] = pure []
parseSource ((Metadata k v):xs)
  | k == "Package" = do
    put v
    parseSource xs
  | k == "Binary" = do
    package <- get
    rest <- parseSource xs
    let r =
          (Source
             { package = package
             , binary = filter (not . null) $ splitOneOf ",\n " v
             }) :
          rest
    return r
  | otherwise = parseSource xs
parseSource (_:xs) = parseSource xs

fromTokens :: [String] -> [Token] -> [(String, [String])]
fromTokens ps ts =
  filter (\(p, _) -> p `elem` ps) $ fromSource <$> evalState (parseSource ts) ""

sources :: [[(String, [String])]] -> Map.Map String [String]
sources = Map.fromList . concat

sourcesFromURIs ::
     [String] -> [String] -> IO (Either [String] (Map.Map String [String]))
sourcesFromURIs vulnerables fss = do
  scs <- mapM (sourcesFromURI vulnerables) fss
  let (errors, results) = partitionEithers scs
  if null errors
    then return . Right $ sources results
    else return $ Left errors

urisFromSuite :: String -> String -> [String]
urisFromSuite base suite = do
  part1 <- ["", "-security", "-updates", "-proposed", "-backports"]
  part2 <- ["main", "universe", "multiverse", "restricted"]
  return $ base <> "/" <> suite <> part1 <> "/" <> part2 <> "/source/Sources.xz"

sourcesFromURI :: [String] -> String -> IO (Either String [(String, [String])])
sourcesFromURI vulnerables uri = do
  content <- openURI uri
  let sourceFile =
        bimap (\err -> uri ++ " : " ++ err) decompressToString content
  let parsed = sourceFile >>= parseWithErrors
  return $ second (fromTokens vulnerables) parsed
  where
    decompressToString = unpack . toStrict . decompress . fromStrict

getSuiteSource ::
     [String] -> String -> IO (Either [String] (Map.Map String [String]))
getSuiteSource packages suite = do
  let urls = urisFromSuite "http://ftp.ubuntu.com/ubuntu/dists" suite
  sourcesFromURIs packages urls
