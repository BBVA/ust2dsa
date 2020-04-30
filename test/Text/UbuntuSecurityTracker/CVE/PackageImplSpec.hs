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
module Text.UbuntuSecurityTracker.CVE.PackageImplSpec where

import Data.UbuntuSecurityTracker.CVE.Package hiding (Package(..))
import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.UbuntuSecurityTracker.CVE.Token hiding (Status(..))

import Data.Maybe (isJust)
import Test.Hspec
import Generic.Random
import GHC.Generics
import Test.QuickCheck

instance Arbitrary T.Status where
  arbitrary = genericArbitrary uniform

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "SIMPLIFY UBUNTU SECURITY TRACKER PACKAGE STATUS" $ do
    describe "when a version is provided" $ do
      it "should map Ubuntu's package status to VULNERABLE" $ do
        mapStatus T.NEEDED (Just "1.0") `shouldBe` (Just $ VULNERABLE "1.0")
        mapStatus T.ACTIVE (Just "1.0") `shouldBe` (Just $ VULNERABLE "1.0")
        mapStatus T.PENDING (Just "1.0") `shouldBe` (Just $ VULNERABLE "1.0")
        mapStatus T.DEFERRED (Just "1.0") `shouldBe` (Just $ VULNERABLE "1.0")
      it "should map Ubuntu's package status to NOTVULNERABLE" $ do
        mapStatus T.DNE (Just "1.0") `shouldBe` (Just $ NOTVULNERABLE "1.0")
        mapStatus T.NEEDSTRIAGE (Just "1.0") `shouldBe`
          (Just $ NOTVULNERABLE "1.0")
        mapStatus T.NOTAFFECTED (Just "1.0") `shouldBe`
          (Just $ NOTVULNERABLE "1.0")
        mapStatus T.IGNORED (Just "1.0") `shouldBe` (Just $ NOTVULNERABLE "1.0")
        mapStatus T.RELEASED (Just "1.0") `shouldBe`
          (Just $ NOTVULNERABLE "1.0")
        mapStatus T.RELEASEDESM (Just "1.0") `shouldBe`
          (Just $ NOTVULNERABLE "1.0")
    describe "when a version isn't provided" $ do
      it "should return Nothing" $ property $
        \x -> mapStatus x Nothing == Nothing
    describe "when the version is invalid" $ do
      it "should return Nothing" $ property $
        \x -> mapStatus x (Just "this is not a version") == Nothing
    describe "when the string contains tilde" $ do
      it "should success when both fragments are valid versions" $ property $
        \x -> isJust $ mapStatus x (Just "1.2.3~ubuntu1")
      it "should fail if any fragment is an invalid version" $ property $
        \x -> mapStatus x (Just "1.2.3~foo bar") == Nothing
      -- TODO: Support multiple versions
