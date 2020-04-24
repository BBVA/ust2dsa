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
import Data.DebianSecurityAnalyzer.CVE (mapCVE)
import Control.Monad

main = do
    files <- getRecord "CVE File Checker"
    mapM parseFile (files :: [String])
  where
    parseAndValidate fn s = do tokens <- parseWithStrError fn s --  >=> fillCVE >=> mapCVE
                               mcve <- fillCVE tokens
                               cve <- mapCVE mcve
                               return cve

    parseWithStrError fn s = case parse cveParser fn s of
                               Left x -> Left $ show x
                               Right y -> Right y


    parseFile :: FilePath -> IO ()
    parseFile fn = do txt <- readFile fn
                      case parseAndValidate fn txt of
                        Right _ -> putStrLn $ fn ++ ": OK"
                        Left s  -> putStrLn $ fn ++ ": " ++ s

    -- parseFile :: Parser a -> String -> IO ()
    -- parseFile p fileName = withFileparseFromFile p fileName >>= either report ok
    --   where
    --     report err = do
    --       putStrLn $ show err
    --       exitFailure
    --       return ()
    --     ok _ = do
    --       putStrLn $ show fileName ++ ": OK"
    --       return ()
