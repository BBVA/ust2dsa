module Text.UbuntuSecurityTracker.CVE where

import Data.Bifunctor
import Text.Parsec

import Control.Monad ((>=>))
import Data.DebianSecurityAnalyzer.CVE (CVE (..), mapCVE)
import Text.UbuntuSecurityTracker.CVE.Parser (parseWithErrors)
import Data.UbuntuSecurityTracker.CVE.Token (Token)
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl (fillCVE)

parseAndValidate :: String -> String -> Either String CVE
parseAndValidate filename content = first addFilenameToError $ parseAndValidate' content
  where
    addFilenameToError :: String -> String
    addFilenameToError e = filename ++ ": " ++ e
    
    parseAndValidate' :: String -> Either String CVE
    parseAndValidate' = parseWithErrors >=> fillCVE >=> mapCVE
