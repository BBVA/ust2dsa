module Text.DebianSecurityAnalyzer.Database where

import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP
import Data.List
import Data.Maybe

renderVulnerability :: CVE -> String
renderVulnerability CVE { name = n , description = d } = n ++ ",," ++ d

renderPackage :: String       -- Release
              -> Int          -- Vulnerability Index (section offset)
              -> String       -- Package Name
              -> CVE          -- Vulnerability
              -> Maybe String -- Formatted Output
renderPackage _ _ _ CVE { affected = [] } = Nothing
renderPackage r o p CVE { affected = aps
                        , priority = pri
                        , isRemote = rmt } =
    Just $ intercalate "," [name, show o, flags, unstable_version, other_versions]
  where
    name = p
    flags = [ 'S', getFlagUrgency pri, getFlagIsRemote rmt, getFlagIsFixAvailable r p aps ]
    unstable_version = fromMaybe "" $ getUnstableVersion p aps
    other_versions = unwords $ getOtherVersions p aps

renderDebsecanDB :: String -> [CVE] -> String
renderDebsecanDB r cs = "VERSION 1\n" ++ sections
  where
    sections = intercalate "\n\n" [ vulnerabilities, affected, sources ]

    vulnerabilities = intercalate "\n" $ fmap renderVulnerability cs
    affected = intercalate "\n" renderedAffected
    renderedAffected = do
      (i, c@CVE { affected = aps }) <- zip [0..] cs
      UP.Package { UP.name = p }  <- aps
      maybe [] return (renderPackage r i p c)
    sources = ""
