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
  deriving (Show, Eq)

mapCVE :: U.CVE -> Either String CVE
mapCVE U.CVE{ U.name=Just n
            , U.description=Just d
            , U.priority=p
            , U.isRemote=r
            , U.affected=aps
            } = Right $ CVE n d p r aps
mapCVE U.CVE{ U.name=Nothing } = Left "CVE identifier missing"
mapCVE _ = Left "fubar cve"
