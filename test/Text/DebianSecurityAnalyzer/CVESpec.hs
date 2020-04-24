module Text.DebianSecurityAnalyzer.CVESpec where

import qualified Data.DebianSecurityAnalyzer.CVE as D
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

import Data.Either
import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "TRANSFORMING UBUNTU'S CVE TO DEBSECAN'S" $ do
    it "should fail when mandatory fields are not present" $ do
      isLeft $ D.mapCVE U.emptyCVE
    it "should transform all field present" $
      do D.mapCVE
           U.emptyCVE
             { U.name = Just "foo"
             , U.description = Just "bar"
             , U.priority = Just U.L
             , U.isRemote = Just True
             , U.affected = [UP.Package "baz" "qux" (UP.VULNERABLE "quux")]
             }
         `shouldBe` Right
           D.CVE
             { D.name = "foo"
             , D.description = "bar"
             , D.priority = Just U.L
             , D.isRemote = Just True
             , D.affected = [UP.Package "baz" "qux" (UP.VULNERABLE "quux")]
             }
