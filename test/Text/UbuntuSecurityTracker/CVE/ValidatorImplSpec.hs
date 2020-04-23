module Text.UbuntuSecurityTracker.CVE.ValidatorImplSpec where

import Data.UbuntuSecurityTracker.CVE
import Data.UbuntuSecurityTracker.CVE.Token
import Test.Hspec
import Text.UbuntuSecurityTracker.CVE.ValidatorImpl

main :: IO ()
main = hspec spec

spec :: Spec
spec
  -- describe "SIMPLIFY UBUNTU SECURITY TRACKER PACKAGE STATUS" $ do
  --   describe "should map Ubuntu's package status to VULNERABLE or NOTVULNERABLE" $ do
  --     mapStatus DNE
  -- -- Still undecided
  -- | NEEDSTRIAGE
  -- -- Not vulnerable
  -- | NOTAFFECTED
  -- -- Vulnerable, but not important
  -- | IGNORED
  -- -- Package is vulnerable
  -- | NEEDED
  -- | ACTIVE
  -- | PENDING
  -- | DEFERRED
  -- -- Fixed
  -- | RELEASED
  -- | RELEASEDESM
  -- deriving (Show, Eq, Ord)
 = do
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
