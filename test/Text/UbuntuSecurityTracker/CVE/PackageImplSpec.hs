module Text.UbuntuSecurityTracker.CVE.PackageImplSpec where

import Data.UbuntuSecurityTracker.CVE.Package hiding (Package(..))
import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.UbuntuSecurityTracker.CVE.Token hiding (Status(..))

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
