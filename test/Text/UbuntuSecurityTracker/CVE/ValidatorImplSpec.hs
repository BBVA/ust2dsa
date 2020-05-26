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
module Text.UbuntuSecurityTracker.CVE.ValidatorImplSpec where

import Data.UbuntuSecurityTracker.CVE
import Data.UbuntuSecurityTracker.CVE.Token
import qualified Data.UbuntuSecurityTracker.CVE.Package as P
import Test.Hspec
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl
import Data.Either

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "FILL STAGED STRUCT" $ do
    it "should return an empty CVE on empty Token list" $
      do fillCVE [] `shouldBe` Right emptyCVE
    it "should fill the name field with the `Candidate` Metadata" $
      do honorToken emptyCVE (Metadata "Candidate" "foo")
         `shouldBe` Right emptyCVE {name = Just "foo"}
    it "should fill the description field with the `Description` Metadata" $
      do honorToken emptyCVE (Metadata "Description" "foo")
         `shouldBe` Right emptyCVE {description = Just "foo"}
    it "should fill the isRemote field with True if the CVSS key has '/AV:N/' (N:network)" $
      do honorToken emptyCVE (Metadata "CVSS" "foo /AV:N/ bar")
         `shouldBe` Right emptyCVE {isRemote = Just True}
    it "should fill the isRemote field with False if the CVSS key has '/AV:[^N]//'" $
      do honorToken emptyCVE (Metadata "CVSS" "bar /AV:W/ baz")
         `shouldBe` Right emptyCVE {isRemote = Just False}
    it "should fill the isRemote field with Nothing if the CVSS key has an empty value" $
      do honorToken emptyCVE (Metadata "CVSS" "")
         `shouldBe` Right emptyCVE {isRemote = Nothing}
    it "should fill the priority field with the `Priority` Metadata (low)" $
      do honorToken emptyCVE (Metadata "Priority" "low")
         `shouldBe` Right emptyCVE {priority = Just L}
    it "should fill the priority field with the `Priority` Metadata (medium)" $
      do honorToken emptyCVE (Metadata "Priority" "medium")
         `shouldBe` Right emptyCVE {priority = Just M}
    it "should fill the priority field with the `Priority` Metadata (high)" $
      do honorToken emptyCVE (Metadata "Priority" "high")
         `shouldBe` Right emptyCVE {priority = Just H}
    it "should fill the priority field with the `Priority` Metadata (critical)" $
      do honorToken emptyCVE (Metadata "Priority" "critical")
         `shouldBe` Right emptyCVE {priority = Just H}
    it "should fill the priority field with the `Priority` Metadata (untriaged)" $
      do honorToken emptyCVE (Metadata "Priority" "untriaged")
         `shouldBe` Right emptyCVE {priority = Nothing}
    it "should fill the priority field with the `Priority` Metadata (negligible)" $
      do honorToken emptyCVE (Metadata "Priority" "negligible")
         `shouldBe` Right emptyCVE {priority = Just L}
    it "should report when the priority field contains something unknown" $
      do honorToken emptyCVE (Metadata "Priority" "very-low-maybe-dontknow")
         `shouldSatisfy`
         isLeft
    it "should ignore any comments" $
      do fillCVE [Ignored "This is a comment", Metadata "Candidate" "bar"]
         `shouldBe` Right emptyCVE {name = Just "bar"}
    it "should ignore any other metadata" $
      do honorToken emptyCVE (Metadata "Foo" "bar") `shouldBe` Right emptyCVE
    it "should drop when package metadata is incomplete" $
      do honorToken emptyCVE (RPS "foo" "bar" DNE Nothing) `shouldBe` Right emptyCVE
    it "should drop when package metadata is not a valid version" $
      do honorToken emptyCVE (RPS "foo" "bar" DNE (Just "not a version")) `shouldBe` Right emptyCVE
    it "should add packages to affected list when package metadata sufficient" $
      do honorToken emptyCVE (RPS "foo" "bar" DNE (Just "1.0"))
         `shouldBe`
         Right emptyCVE{affected=[P.Package "foo" "bar" (P.NONVULNERABLE "1.0")]}
