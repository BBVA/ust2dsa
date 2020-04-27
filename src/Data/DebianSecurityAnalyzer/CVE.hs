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
mapCVE U.CVE{ U.name=Nothing
            , U.description=Nothing } = Left "CVE identifier and description missing"
mapCVE U.CVE{ U.name=Nothing } = Left "CVE identifier missing"
mapCVE U.CVE{ U.description=Nothing } = Left "CVE description missing"


getUnstableVersion :: String -> [UP.Package] -> Maybe String
getUnstableVersion p [] = Nothing
getUnstableVersion p ( UP.Package{ UP.name=n
                                 , UP.status=UP.NOTVULNERABLE v }:ps )
  | n == p = Just v
  | otherwise = getUnstableVersion p ps
