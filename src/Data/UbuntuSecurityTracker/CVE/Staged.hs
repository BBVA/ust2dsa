{-# LANGUAGE DuplicateRecordFields #-}

module Data.UbuntuSecurityTracker.CVE.Staged
    ( Staged (..)
    , Priority (..)
    , emptyStaged
    , AffectedPackageStatus (..)
    , AffectedPackage (..)) where


data Priority = L | M | H deriving (Show, Eq, Ord)

data AffectedPackageStatus = VULNERABLE String
                           | NONVULNERABLE String
                           deriving (Show, Eq, Ord)

data AffectedPackage =
     AffectedPackage { release :: String
                     , packageName :: String
                     , status :: AffectedPackageStatus
                     } deriving (Show, Eq, Ord)

data Staged =
     Staged { name :: Maybe String
            , description :: Maybe String
            , priority :: Maybe Priority
            , isRemote :: Maybe Bool
            , affectedPackages :: [AffectedPackage]
            } deriving (Show, Eq)


emptyStaged = Staged { name = Nothing
                     , description = Nothing
                     , priority = Nothing
                     , isRemote = Nothing
                     , affectedPackages = []
                     }