module Data.DebianSecurityAnalyzer.CVE where

import Control.Applicative
import Data.Foldable
import Data.Maybe
import Data.Bool
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
mapCVE U.CVE { U.name = Just n
             , U.description = Just d
             , U.priority = p
             , U.isRemote = r
             , U.affected = aps
             } = Right $ CVE n d p r aps
mapCVE U.CVE {U.name = Nothing, U.description = Nothing} =
  Left "CVE identifier and description missing"
mapCVE U.CVE {U.name = Nothing} = Left "CVE identifier missing"
mapCVE U.CVE {U.description = Nothing} = Left "CVE description missing"

combineFilters :: [a -> Bool] -> a -> Bool
combineFilters filters x = and (filters <*> pure x)

getUnstableVersion :: String -> [UP.Package] -> Maybe String
getUnstableVersion p aps =
  let develPackages = filter (isVulnerableRelease "devel") aps
      upstreamPackages = filter (isVulnerableRelease "upstream") aps
   in firstVersion develPackages <|> firstVersion upstreamPackages
  where
    firstVersion :: [UP.Package] -> Maybe String
    firstVersion xs = (UP.getVersion . UP.status) <$> listToMaybe xs
    isVulnerableRelease :: String -> (UP.Package -> Bool)
    isVulnerableRelease r =
      combineFilters
        [ (== p) . UP.name
        , not . UP.isVulnerable . UP.status
        , (== r) . UP.release
        ]

getOtherVersions :: String -> [UP.Package] -> [String]
getOtherVersions p aps =
  let stablePackages = filter isStableAndVulnerable aps
   in version <$> stablePackages
  where
    version :: UP.Package -> String
    version = UP.getVersion . UP.status
    isStableAndVulnerable :: UP.Package -> Bool
    isStableAndVulnerable =
      combineFilters
        [ (== p) . UP.name
        , not . UP.isVulnerable . UP.status
        , (/= "devel") . UP.release
        , (/= "upstream") . UP.release
        ]

getFlagUrgency :: Maybe U.Priority -> Char
getFlagUrgency = maybe ' ' (head . show)

getFlagIsRemote :: Maybe Bool -> Char
getFlagIsRemote = maybe '?' (bool ' ' 'R')

getFlagIsFixAvailable :: String -> String -> [UP.Package] -> Char
getFlagIsFixAvailable r p [] = ' '
getFlagIsFixAvailable r p [ap] = bool 'F' ' ' (not $ isFixed ap)
  where
    isFixed =
      combineFilters
        [ (== r) . UP.release
        , (== p) . UP.name
        , not . UP.isVulnerable . UP.status ]
