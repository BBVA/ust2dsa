{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Generic
-- import Text.Parsec (Parser)
import System.Exit (exitFailure)
import Text.Parsec (parse)
import Text.Parsec.String (Parser (..), parseFromFile)
import Text.UbuntuSecurityTracker.CVE.Parser (cveParser)
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl (fillCVE)
import Text.DebianSecurityAnalyzer.Database (renderDebsecanDB)
import Data.DebianSecurityAnalyzer.CVE (mapCVE, CVE)
import Control.Monad
import Data.Either

data Args = Args String [String]
            deriving (Generic, Show)

instance ParseRecord Args

main = do
    (Args release files) <- getRecord "Ubuntu Security Tracker To Debsecan File"
    parsed <- mapM parseFile files
    putStrLn $ renderDebsecanDB release (rights parsed)
  where
    parseAndValidate fn s = do tokens <- parseWithStrError fn s --  >=> fillCVE >=> mapCVE
                               mcve <- fillCVE tokens
                               cve <- mapCVE mcve
                               return cve

    parseWithStrError fn s = case parse cveParser fn s of
                               Left x -> Left $ show x
                               Right y -> Right y


    parseFile :: FilePath -> IO (Either String CVE)
    parseFile fn = do txt <- readFile fn
                      return $ parseAndValidate fn txt
