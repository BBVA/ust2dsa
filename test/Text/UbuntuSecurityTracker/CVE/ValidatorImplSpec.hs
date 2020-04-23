module Text.UbuntuSecurityTracker.CVE.ValidatorImplSpec where

import Data.UbuntuSecurityTracker.CVE
import qualified Data.UbuntuSecurityTracker.CVE.Token as T (Status(..))
import Data.UbuntuSecurityTracker.CVE.Token hiding (Status(..))
import qualified Data.UbuntuSecurityTracker.CVE.Package as P (Status(..))
import Data.UbuntuSecurityTracker.CVE.Package hiding (Status(..), Package (..))
import Test.Hspec
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "SIMPLIFY UBUNTU SECURITY TRACKER PACKAGE STATUS" $ do
    it "should map Ubuntu's package status to VULNERABLE" $ do
      mapStatus T.NEEDED (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.ACTIVE (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.PENDING (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
      mapStatus T.DEFERRED (Just "1.0") `shouldBe` (P.VULNERABLE "1.0")
    it "should map Ubuntu's package status to NOTVULNERABLE" $ do
      mapStatus T.DNE (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.NEEDSTRIAGE (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.NOTAFFECTED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.IGNORED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.RELEASED (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
      mapStatus T.RELEASEDESM (Just "1.0") `shouldBe` (P.NOTVULNERABLE "1.0")
  describe "FILL STAGED STRUCT" $ do
    it "should return an empty CVE on empty Token list" $
      do fillCVE [] `shouldBe` Right emptyCVE
    it "should fill the name field with the `Candidate` Metadata" $
      do honorToken emptyCVE (Metadata "Candidate" "foo")
         `shouldBe` Right emptyCVE {name = Just "foo"}
    it "should fill the description field with the `Description` Metadata" $
      do honorToken emptyCVE (Metadata "Description" "foo")
         `shouldBe` Right emptyCVE {description = Just "foo"}
    it "should fill the priority field with the `Priority` Metadata (low)" $
      do honorToken emptyCVE (Metadata "Priority" "low")
         `shouldBe` Right emptyCVE {priority = Just L}
    it "should fill the priority field with the `Priority` Metadata (medium)" $
      do honorToken emptyCVE (Metadata "Priority" "medium")
         `shouldBe` Right emptyCVE {priority = Just M}
    it "should fill the priority field with the `Priority` Metadata (high)" $
      do honorToken emptyCVE (Metadata "Priority" "high")
         `shouldBe` Right emptyCVE {priority = Just H}
    it "should report when the priority field contains something unknown" $
      do honorToken emptyCVE (Metadata "Priority" "very-low-maybe-dontknow")
         `shouldBe` Left "unknown priority value"
    it "should ignore any comments" $
      do fillCVE [Ignored "This is a comment", Metadata "Candidate" "bar"]
         `shouldBe` Right emptyCVE {name = Just "bar"}
    it "should ignore any other metadata" $
      do honorToken emptyCVE (Metadata "Foo" "bar") `shouldBe` Right emptyCVE
