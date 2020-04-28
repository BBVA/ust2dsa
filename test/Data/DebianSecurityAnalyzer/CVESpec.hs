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
  describe "EXTRACTING DEBSECAN FEATURES FROM CVE" $ do
    describe "getUnstableVersion extracts the unstable version from a list of affected packages" $ do
      it "should return Nothing when no packages are affected" $ do
        D.getUnstableVersion "foo" [] `shouldBe` Nothing
      it "should return Nothing when affected packages don't match the given name" $ do
        D.getUnstableVersion "foo" [ UP.Package "upstream" "bar" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Nothing
      it "should return Just the version when an affected package match the given name" $ do
        D.getUnstableVersion "foo" [ UP.Package "upstream" "foo" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Just "1.0"
      it "should return Just the version when any affected package match the given name" $ do
        D.getUnstableVersion "foo" [ UP.Package "upstream" "bar" (UP.NOTVULNERABLE "2.0")
                                   , UP.Package "upstream" "foo" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Just "1.0"
      it "should return Just the version when any affected package match the given name (II)" $ do
        D.getUnstableVersion "foo" [ UP.Package "upstream" "bar" (UP.VULNERABLE "2.0")
                                   , UP.Package "upstream" "foo" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Just "1.0"
      it "should return Nothing if devel and upstream suite are not present" $ do
        D.getUnstableVersion "foo" [ UP.Package "bionic" "bar" (UP.VULNERABLE "2.0")
                                   , UP.Package "bionic" "foo" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Nothing
      it "should return devel version preferably" $ do
        D.getUnstableVersion "foo" [ UP.Package "upstream" "foo" (UP.NOTVULNERABLE "2.0")
                                   , UP.Package "devel" "foo" (UP.NOTVULNERABLE "1.0") ]
        `shouldBe`
        Just "1.0"
      it "should return devel version preferably (II)" $ do
        D.getUnstableVersion "foo" [ UP.Package "devel" "foo" (UP.NOTVULNERABLE "1.0")
                                   , UP.Package "upstream" "foo" (UP.NOTVULNERABLE "2.0") ]
        `shouldBe`
        Just "1.0"
    describe "getUnstableVersion extracts the unstable version from a list of affected packages" $ do
      it "should return an empty list when no packages are affected" $ do
        D.getOtherVersions "foo" [] `shouldBe` []
