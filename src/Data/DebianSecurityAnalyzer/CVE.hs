module Data.DebianSecurityAnalyzer.CVE where

import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

data CVE =
  CVE
    { name :: String
    , description :: String
    , priority :: Maybe U.Priority
    , isRemote :: Maybe Bool
    , affected :: [UP.Package]
    }
  deriving (Show)

mapCVE :: U.CVE -> Either String CVE
mapCVE _ = undefined
