{-# LANGUAGE DuplicateRecordFields, OverloadedStrings #-}

module Data.UbuntuCVE
    ( Status (..)
    , Staged (..)
    , CVE (..)
    , toValidCVE
    , emptyStaged
    , fillStaged
    , Priority (..)
    , cs
    , cs2
    , toAffectedPackageStatus
    , AffectedPackageStatus (..)
    , cveToDebsecanVulnerability
    , cvesToDebsecan
    , getUnstableVersion
    , getAffectedPackage
    , getPackageNames
    , versioning
    ) where

import Data.List
import qualified Data.Text as T
import Data.Versions
import Data.Char
import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

isValidVersion :: String -> Bool
isValidVersion s = case parsedVersion of
                     Right _ -> containsNumber s
                     Left _ -> False
  where
    containsNumber [] = False
    containsNumber (x:xs) = isDigit x || containsNumber xs
    parsedVersion  = versioning (T.pack (replacingTilde s))
    replacingTilde = fmap (\x -> if x == '~' then '+' else x)

toAffectedPackageStatus :: Status -> Maybe Notes -> Maybe AffectedPackageStatus
toAffectedPackageStatus DNE _ = Nothing
toAffectedPackageStatus NEEDSTRIAGE _ = Nothing
toAffectedPackageStatus IGNORED _ = Nothing
toAffectedPackageStatus NOTAFFECTED (Just txt)
  | isValidVersion txt = Just (NONVULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus NEEDED (Just txt)
  | isValidVersion txt = Just (VULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus ACTIVE (Just txt)
  | isValidVersion txt = Just (VULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus PENDING (Just txt)
  | isValidVersion txt = Just (VULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus DEFERRED (Just txt)
  | isValidVersion txt = Just (VULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus RELEASED (Just txt)
  | isValidVersion txt = Just (NONVULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus RELEASEDESM (Just txt)
  | isValidVersion txt = Just (NONVULNERABLE txt)
  | otherwise          = Nothing
toAffectedPackageStatus _ _ = Nothing

fillStaged :: Staged -> [Token] -> Staged
fillStaged cve [] = cve
fillStaged cve ((Metadata key value):cs)
  | key == "Candidate" = fillStaged cve{name=Just value} cs
  | key == "Description" = fillStaged cve{description=Just value} cs
  | key == "Priority" = case value of
                          "low" -> fillStaged cve{priority=Just L} cs
                          "medium" -> fillStaged cve{priority=Just M} cs
                          "high" -> fillStaged cve{priority=Just H} cs
                          _ -> fillStaged cve cs
  | otherwise          = fillStaged cve cs
-- fillStaged cve@Staged{affectedPackages=ap} ((RPS "upstream" p s n):cs) = fillStaged cve cs
fillStaged cve@Staged{affectedPackages=ap} ((RPS r p s n):cs) =
   case toAffectedPackageStatus s n of
     Nothing    -> fillStaged cve cs
     (Just aps) -> fillStaged cve{affectedPackages=insert (affectedPackage aps) ap} cs
  where
    affectedPackage s = AffectedPackage {release=r, packageName=p, status=s}
fillStaged cve (_:cs) = fillStaged cve cs

-------

cs = [ Metadata "Candidate" "CVE-2020-11111"
     , Metadata "Priority" "medium"
     , Metadata "Description" "Something bad happened, bla, blah, blah, blah, blah, blah bla, blah, blah, blah, blah, blahbla, blah, blah, blah, blah, blah ..."
     , Metadata "PublicDate" "2019-11-27 18:15:00 UTC"
     , RPS "bionic" "openssl" RELEASED (Just "1234")
     , RPS "devel" "openssl" RELEASED (Just "1248")
     , RPS "devel" "linux" RELEASED (Just "5555")
     ]

cs2 = [ Metadata "Candidate" "CVE-2020-11111"
     , Metadata "Priority" "medium"
     , Metadata "Description" "Something bad happened, bla, blah, blah, blah, blah, blah bla, blah, blah, blah, blah, blahbla, blah, blah, blah, blah, blah ..."
     , Metadata "PublicDate" "2019-11-27 18:15:00 UTC"
     , RPS "bionic" "openssl" RELEASED (Just "1234")
     ]

--

data CVE =
     CVE { name :: String
         , description :: String
         , priority :: Maybe Priority
         , isRemote :: Maybe Bool
         , affectedPackages :: [AffectedPackage]
         } deriving (Show)


toValidCVE :: Staged -> Maybe CVE
toValidCVE Staged{ name=Just n
                    , description=Just d
                    , priority=pri
                    , isRemote=ir
                    , affectedPackages=ap} = Just CVE{ name=n,
                                                       description=d,
                                                       priority=pri,
                                                       isRemote=ir,
                                                       affectedPackages=ap }
toValidCVE _ = Nothing

--

-- affectedPackageToDebsecan :: Int -> AffectedPackage -> String -> [String] -> String
-- affectedPackageToDebsecan o AffectedPackage{name=n, status=s} uv ov =
--     intercalate "," [n, flags, uv, ov]
--   where
--     flags = undefined


-- <package_name> -> [..] -> (unstable_version, [other_versions])
getUnstableVersion :: String -> [AffectedPackage] -> Maybe String
getUnstableVersion _ [] = Nothing
getUnstableVersion s (AffectedPackage{packageName=n, release=r, status=(NONVULNERABLE v)}:aps)
  | s==n && r == "upstream" = Just v
  | otherwise            = getUnstableVersion s aps
getUnstableVersion s (_:aps) = getUnstableVersion s aps


getOtherVersions :: String -> [AffectedPackage] -> [String]
getOtherVersions _ [] = []
getOtherVersions s (AffectedPackage{packageName=n, release=r, status=(NONVULNERABLE v)}:aps)
  | s==n && r /= "upstream" = v:(getOtherVersions s aps)
  | otherwise            = getOtherVersions s aps
getOtherVersions s (_:aps) = getOtherVersions s aps

getPackageNames :: [AffectedPackage] -> [String]
getPackageNames xs = nub $ getName <$> xs
  where
    getName AffectedPackage{packageName=n} = n

isFixAvailable :: String -> String -> [AffectedPackage] -> Bool
isFixAvailable n r [] = False
isFixAvailable n r (AffectedPackage{packageName=n', release=r', status=(NONVULNERABLE _)}:aps)
  | n == n' && r == r' = True
  | otherwise = isFixAvailable n r aps
isFixAvailable n r (_:aps) = isFixAvailable n r aps


cveToDebsecanVulnerablePackage :: String -> (Int, CVE) -> [String]
cveToDebsecanVulnerablePackage suite (offset, CVE{affectedPackages=aps, priority=pri, isRemote=ir}) =
    [intercalate "," [p, show offset, flags p, unstableVersion p, otherVersions p] | p <- packageNames]
  where
    packageNames = getPackageNames aps
    unstableVersion p = maybe "" id $ getUnstableVersion p aps
    otherVersions p = intercalate " " $ nub $ getOtherVersions p aps

    isRemoteToFlag (Just True) = "R"
    isRemoteToFlag (Just False) = " "
    isRemoteToFlag Nothing = "?"

    priorityToFlag (Just x) = show x
    priorityToFlag Nothing = " "

    fixFlag p = if isFixAvailable p suite aps then "F" else " "

    flags p = "S" ++ priorityToFlag pri ++ isRemoteToFlag ir ++ fixFlag p


getAffectedPackage :: CVE -> [AffectedPackage]
getAffectedPackage CVE{affectedPackages=aps} = aps

cveToDebsecanVulnerability :: CVE -> String
cveToDebsecanVulnerability CVE{name=n, description=d} = n ++ ",," ++ (take 74 inlineDescription)
  where
    inlineDescription = fmap (\x -> if x=='\n' then ' ' else x) d

cvesToDebsecan :: String -> [CVE] -> String
cvesToDebsecan suite cves = intercalate "\n" ["VERSION 1", vulnerabilities, "", susceptibility, sources]
  where
    vulnerabilities = intercalate "\n" $ fmap cveToDebsecanVulnerability cves
    susceptibility = intercalate "\n" $ concat $ fmap (cveToDebsecanVulnerablePackage suite) (zip [0..] cves)
    sources = ""