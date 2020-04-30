{-# LANGUAGE OverloadedStrings #-}
{-|
Copyright 2020 Banco Bilbao Vizcaya Argentaria, S.A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-}

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
    describe "getOtherVersions extracts the unstable version from a list of affected packages" $ do
      it "should return an empty list when no packages are affected" $ do
        D.getOtherVersions "foo" [] `shouldBe` []
      it "should return an empty list when no packages match the given name" $ do
        D.getOtherVersions "foo" [ UP.Package "devel" "bar" (UP.NOTVULNERABLE "1.0")
                                 , UP.Package "bionic" "baz" (UP.VULNERABLE "2.0") ]
        `shouldBe`
        []
      it "should return an empty list when no packages match the given name" $ do
        D.getOtherVersions "foo" [ UP.Package "bionic" "bar" (UP.NOTVULNERABLE "1.0")
                                 , UP.Package "devel" "baz" (UP.VULNERABLE "2.0") ]
        `shouldBe`
        []
      it "should return a list with the matching affected versions" $ do
        D.getOtherVersions "foo" [ UP.Package "devel" "foo" (UP.VULNERABLE "1.0")
                                 , UP.Package "bionic" "foo" (UP.VULNERABLE "2.0")
                                 , UP.Package "upstream" "foo" (UP.VULNERABLE "3.0")
                                 , UP.Package "devel" "foo" (UP.NOTVULNERABLE "4.0")
                                 , UP.Package "bionic" "foo" (UP.NOTVULNERABLE "5.0")
                                 , UP.Package "upstream" "foo" (UP.NOTVULNERABLE "6.0") ]
        `shouldBe`
        ["5.0"]
      it "should not return duplicates" $ do
        D.getOtherVersions "foo" [ UP.Package "bar" "foo" (UP.NOTVULNERABLE "1.0")
                                 , UP.Package "baz" "foo" (UP.NOTVULNERABLE "1.0")
                                 , UP.Package "qux" "foo" (UP.NOTVULNERABLE "2.0") ]
        `shouldBe`
        ["1.0", "2.0"]
    describe "getFlagUrgency extracts the Urgency flag" $ do
      it "should return an H for High Priority" $ do
        D.getFlagUrgency (Just U.H)
        `shouldBe`
        'H'
      it "should return an M for Medium Priority" $ do
        D.getFlagUrgency (Just U.M)
        `shouldBe`
        'M'
      it "should return an L for Low Priority" $ do
        D.getFlagUrgency (Just U.L)
        `shouldBe`
        'L'
      it "should return an <space> for Undefined Priority" $ do
        D.getFlagUrgency Nothing
        `shouldBe`
        ' '
    describe "getFlagIsRemote extracts the Remote flag" $ do
      it "should return an R when it is remotely exploitable" $ do
        D.getFlagIsRemote (Just True)
        `shouldBe`
        'R'
      it "should return an <space> when it is not remotely exploitable" $ do
        D.getFlagIsRemote (Just False)
        `shouldBe`
        ' '
      it "should return a ? when it is not defined" $ do
        D.getFlagIsRemote Nothing
        `shouldBe`
        '?'
    describe "getFlagIsFixAvailable determines if there is a fixed version for this suite" $ do
      it "should return an <space> when there is no fix available" $ do
        D.getFlagIsFixAvailable "bionic" "foo" []
        `shouldBe`
        ' '
      it "should return an F when there is a fix available" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [UP.Package "bionic" "foo" (UP.NOTVULNERABLE "1.0")]
        `shouldBe`
        'F'
      it "should return an <space> when there is no fix available (status mismatch)" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [UP.Package "bionic" "foo" (UP.VULNERABLE "1.0")]
        `shouldBe`
        ' '
      it "should return an <space> when there is no fix available (package mismatch)" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [UP.Package "bionic" "bar" (UP.NOTVULNERABLE "1.0")]
        `shouldBe`
        ' '
      it "should return an <space> when there is no fix available (release mismatch)" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [UP.Package "trionic" "foo" (UP.NOTVULNERABLE "1.0")]
        `shouldBe`
        ' '
      it "should return an F when there is a fix available (multi-entry list)" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [ UP.Package "bionic" "foo" (UP.VULNERABLE "1.0")
                                               , UP.Package "bionic" "foo" (UP.NOTVULNERABLE "1.1") ]
        `shouldBe`
        'F'
      it "should return an <space> when there is no fix available (multi-entry list)" $ do
        D.getFlagIsFixAvailable "bionic" "foo" [ UP.Package "bionic" "foo" (UP.VULNERABLE "1.0")
                                               , UP.Package "devel" "foo" (UP.NOTVULNERABLE "1.1") ]
        `shouldBe`
        ' '
