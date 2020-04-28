module Data.DebianSecurityAnalyzer.CVE where

import Control.Applicative
import Data.Foldable
import Data.Maybe.HT
import Data.Monoid
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
getUnstableVersion p aps = ( first ((== "devel") . UP.release) aps )
                       <|> ( first ((== "upstream") . UP.release) aps )
  where
    first :: (UP.Package -> Bool) -> [UP.Package] -> Maybe String
    first f xs = getFirst . foldMap notVulnerableVersion $ filter f xs

    notVulnerableVersion :: UP.Package -> First String
    notVulnerableVersion UP.Package{ UP.name=n
                                   , UP.status=UP.NOTVULNERABLE v }
                                   = First $ toMaybe (n == p) v
    notVulnerableVersion _ = First Nothing

getOtherVersions :: String -> [UP.Package] -> [String]
getOtherVersions _ [] = []
getOtherVersions p aps = UP.getVersion <$> filter ( and . applyAllFilters ) aps
  where
    isNotVulnerable :: UP.Package -> Bool
    isNotVulnerable UP.Package{UP.status=UP.VULNERABLE _} = False
    isNotVulnerable UP.Package{UP.status=UP.NOTVULNERABLE _} = True

    isNotInDevel :: UP.Package -> Bool
    isNotInDevel = (/= "devel") . UP.release

    isNotInUpstream :: UP.Package -> Bool
    isNotInUpstream = (/= "upstream") . UP.release
     
    isSamePackage :: UP.Package -> Bool
    isSamePackage = (== p) . UP.name

    applyAllFilters :: UP.Package -> [Bool]
    applyAllFilters = ( [ isSamePackage, isNotVulnerable, isNotInDevel, isNotInUpstream ] <*> ) . pure
