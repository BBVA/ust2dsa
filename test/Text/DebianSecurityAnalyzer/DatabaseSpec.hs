module Text.DebianSecurityAnalyzer.DatabaseSpec where

import Data.DebianSecurityAnalyzer.CVE
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP
import Text.DebianSecurityAnalyzer.Database

import Test.Hspec
import Test.QuickCheck
import Generic.Random

import GHC.Generics

instance Arbitrary U.Priority where
  arbitrary = genericArbitraryU

instance Arbitrary UP.Status where
  arbitrary = genericArbitraryU

instance Arbitrary UP.Package where
  arbitrary = genericArbitraryU

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "VULNERABILITIES SECTION" $ do
    describe "renderVulnerability: CVE to debsecan's vulnerability format" $ do
      it "should respect debsecan's format (empty fields)" $
        do renderVulnerability
             CVE
               { name = ""
               , description = ""
               , priority = Nothing
               , isRemote = Nothing
               , affected = []
               }
           `shouldBe` ",,"
      it "should respect debsecan's format (populated fields)" $
        property $ \n d p r aps ->
          renderVulnerability
            CVE
              { name = n
              , description = d
              , priority = p
              , isRemote = r
              , affected = aps
              }
          `shouldBe`
          n ++ ",," ++ d
