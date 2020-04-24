{-# LANGUAGE OverloadedStrings #-}

module Data.DebianSecurityAnalyzer.CVESpec where

import qualified Data.DebianSecurityAnalyzer.CVE as D
import qualified Data.UbuntuSecurityTracker.CVE as U
import qualified Data.UbuntuSecurityTracker.CVE.Package as UP

import Data.Either
import Data.Text (isInfixOf, pack)
import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "TRANSFORMING UBUNTU'S CVE TO DEBSECAN'S" $ do
    let completeCVE =
          U.CVE
            { U.name = Just "foo"
            , U.description = Just "bar"
            , U.priority = Just U.L
            , U.isRemote = Just True
            , U.affected = [UP.Package "baz" "qux" (UP.VULNERABLE "quux")]
            }
    it "should fail when mandatory fields are not present" $ do
      isLeft $ D.mapCVE U.emptyCVE
    it "should transform all field present" $
      do D.mapCVE completeCVE
         `shouldBe` Right
        D.CVE
          { D.name = "foo"
          , D.description = "bar"
          , D.priority = Just U.L
          , D.isRemote = Just True
          , D.affected = [UP.Package "baz" "qux" (UP.VULNERABLE "quux")]
          }
    describe "inform about the missing fields" $
      do
      it "should inform about missing identifier" $
        do D.mapCVE completeCVE{ U.name=Nothing }
          `shouldSatisfy`
          (isInfixOf "identifier") . pack . fromLeft ""
      it "should inform about missing description" $
        do D.mapCVE completeCVE{ U.description=Nothing }
          `shouldSatisfy`
          (isInfixOf "description") . pack . fromLeft ""
