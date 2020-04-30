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
