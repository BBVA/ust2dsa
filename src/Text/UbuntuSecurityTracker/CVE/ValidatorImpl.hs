{-# LANGUAGE MultiWayIf #-}

module Text.UbuntuSecurityTracker.CVE.ValidatorImpl
  ( honorToken
  -- , fillStaged
  ) where

import Data.UbuntuSecurityTracker.CVE.Token
import Data.UbuntuSecurityTracker.CVE.Staged

-- fillStaged :: [Token] -> Staged
-- fillStaged = foldl honorToken emptyStaged

-- TODO: Fill isRemote field when a CVSS parser is available
honorToken :: Staged -> Token -> Either String Staged
honorToken s (Ignored _) = Right s
honorToken s (Metadata k v)
  | k == "Candidate"         = Right s{name=Just v}
  | k == "Description"       = Right s{description=Just v}
  | k == "Priority"          =
         if | v == "high"   -> Right s{priority=Just H}
            | v == "medium" -> Right s{priority=Just M}
            | v == "low"    -> Right s{priority=Just L}
            | otherwise     -> Left "unknown priority value"
  | otherwise                = Right s
