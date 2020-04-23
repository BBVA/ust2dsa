{-# LANGUAGE DuplicateRecordFields, OverloadedStrings #-}

module Data.UbuntuCVE
  ( Status(..)
  , CVE(..)
  , toValidCVE
  , to
  , cveToDebsecanVulnerability
  , cvesToDebsecan
  , getUnstableVersion
  , getPackage
  , getPackageNames
  , versioning
  ) where

import Data.Char
import Data.List
import qualified Data.Text as T
import qualified Data.UbuntuSecurityTracker.CVE as C
import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import Data.UbuntuSecurityTracker.CVE.Token
import Data.Versions

isValidVersion :: String -> Bool
isValidVersion s =
  case parsedVersion of
    Right _ -> containsNumber s
    Left _ -> False
  where
    containsNumber [] = False
    containsNumber (x:xs) = isDigit x || containsNumber xs
    parsedVersion = versioning (T.pack (replacingTilde s))
    replacingTilde =
      fmap
        (\x ->
           if x == '~'
             then '+'
             else x)

to :: Status -> Maybe Notes -> Maybe P.Status
to DNE _ = Nothing
to NEEDSTRIAGE _ = Nothing
to IGNORED _ = Nothing
to NOTAFFECTED (Just txt)
  | isValidVersion txt = Just (P.NOTVULNERABLE txt)
  | otherwise = Nothing
to NEEDED (Just txt)
  | isValidVersion txt = Just (P.VULNERABLE txt)
  | otherwise = Nothing
to ACTIVE (Just txt)
  | isValidVersion txt = Just (P.VULNERABLE txt)
  | otherwise = Nothing
to PENDING (Just txt)
  | isValidVersion txt = Just (P.VULNERABLE txt)
  | otherwise = Nothing
to DEFERRED (Just txt)
  | isValidVersion txt = Just (P.VULNERABLE txt)
  | otherwise = Nothing
to RELEASED (Just txt)
  | isValidVersion txt = Just (P.NOTVULNERABLE txt)
  | otherwise = Nothing
to RELEASEDESM (Just txt)
  | isValidVersion txt = Just (P.NOTVULNERABLE txt)
  | otherwise = Nothing
to _ _ = Nothing

data CVE =
  CVE
    { name :: String
    , description :: String
    , priority :: Maybe C.Priority
    , isRemote :: Maybe Bool
    , affected :: [P.Package]
    }
  deriving (Show)

toValidCVE :: C.CVE -> Maybe CVE
toValidCVE C.CVE { name = Just n
                 , description = Just d
                 , priority = pri
                 , isRemote = ir
                 , affected = ap
                 } =
  Just
    CVE
      {name = n, description = d, priority = pri, isRemote = ir, affected = ap}
toValidCVE _ = Nothing

--
-- affectedPackageToDebsecan :: Int -> P.Package -> String -> [String] -> String
-- affectedPackageToDebsecan o P.Package{name=n, status=s} uv ov =
--     intercalate "," [n, flags, uv, ov]
--   where
--     flags = undefined
-- <package_name> -> [..] -> (unstable_version, [other_versions])
getUnstableVersion :: String -> [P.Package] -> Maybe String
getUnstableVersion _ [] = Nothing
getUnstableVersion s (P.Package { name = n
                                , release = r
                                , status = (P.NOTVULNERABLE v)
                                }:aps)
  | s == n && r == "upstream" = Just v
  | otherwise = getUnstableVersion s aps
getUnstableVersion s (_:aps) = getUnstableVersion s aps

getOtherVersions :: String -> [P.Package] -> [String]
getOtherVersions _ [] = []
getOtherVersions s (P.Package { name = n
                              , release = r
                              , status = (P.NOTVULNERABLE v)
                              }:aps)
  | s == n && r /= "upstream" = v : (getOtherVersions s aps)
  | otherwise = getOtherVersions s aps
getOtherVersions s (_:aps) = getOtherVersions s aps

getPackageNames :: [P.Package] -> [String]
getPackageNames xs = nub $ getName <$> xs
  where
    getName P.Package {name = n} = n

isFixAvailable :: String -> String -> [P.Package] -> Bool
isFixAvailable n r [] = False
isFixAvailable n r (P.Package { name = n'
                              , release = r'
                              , status = (P.NOTVULNERABLE _)
                              }:aps)
  | n == n' && r == r' = True
  | otherwise = isFixAvailable n r aps
isFixAvailable n r (_:aps) = isFixAvailable n r aps

cveToDebsecanVulnerablePackage :: String -> (Int, CVE) -> [String]
cveToDebsecanVulnerablePackage suite (offset, CVE { affected = aps
                                                  , priority = pri
                                                  , isRemote = ir
                                                  }) =
  [ intercalate
    ","
    [p, show offset, flags p, unstableVersion p, otherVersions p]
  | p <- names
  ]
  where
    names = getPackageNames aps
    unstableVersion p = maybe "" id $ getUnstableVersion p aps
    otherVersions p = intercalate " " $ nub $ getOtherVersions p aps
    isRemoteToFlag (Just True) = "R"
    isRemoteToFlag (Just False) = " "
    isRemoteToFlag Nothing = "?"
    priorityToFlag (Just x) = show x
    priorityToFlag Nothing = " "
    fixFlag p =
      if isFixAvailable p suite aps
        then "F"
        else " "
    flags p = "S" ++ priorityToFlag pri ++ isRemoteToFlag ir ++ fixFlag p

getPackage :: CVE -> [P.Package]
getPackage CVE {affected = aps} = aps

cveToDebsecanVulnerability :: CVE -> String
cveToDebsecanVulnerability CVE {name = n, description = d} =
  n ++ ",," ++ (take 74 inlineDescription)
  where
    inlineDescription =
      fmap
        (\x ->
           if x == '\n'
             then ' '
             else x)
        d

cvesToDebsecan :: String -> [CVE] -> String
cvesToDebsecan suite cves =
  intercalate "\n" ["VERSION 1", vulnerabilities, "", susceptibility, sources]
  where
    vulnerabilities = intercalate "\n" $ fmap cveToDebsecanVulnerability cves
    susceptibility =
      intercalate "\n" $
      concat $ fmap (cveToDebsecanVulnerablePackage suite) (zip [0 ..] cves)
    sources = ""
